package s3api

import (
	"bufio"
	"context"
	"crypto/md5" //nolint:gosec // S3 defines the part ETag as the MD5 of the part bytes
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/amwolff/awsig"

	"github.com/xMlex/s3vault/internal/domain"
	"github.com/xMlex/s3vault/internal/identity"
	"github.com/xMlex/s3vault/internal/port"
	"github.com/xMlex/s3vault/internal/s3api/s3err"
	sessions "github.com/xMlex/s3vault/internal/s3api/session"
	"github.com/xMlex/s3vault/internal/service"
	"github.com/xMlex/s3vault/internal/spool"
)

// Multipart in the S3 facade.
//
// The gateway assembles parts itself, over the same path a PutObject body
// takes: each UploadPart is spooled to a file, CompleteMultipartUpload
// concatenates them, and the result reaches the storage through the ordinary
// archive.UploadFile — so the gateway adds exactly one layer, the same one a
// single PUT would have added (architecture.md, "Layer ownership": assembly
// happens before the frame, never after it).
//
// The client does not know the gateway does this, and must not. The AWS SDK
// uploader picks between one PutObject and multipart at its part size
// (s3.multipart_part_size, default 5 MiB), and that is the SDK's decision, not
// s3vault's: a client-side fallback would make the client's behaviour depend on
// what the peer can do. See docs/multipart.md §5.

// S3 multipart specification limits.
const (
	// maxParts is the S3 limit on parts per upload.
	maxParts = 10000
	// minPartSize applies to every part except the last.
	minPartSize = 5 << 20 // 5 MiB
	// maxPartSize is the S3 limit on the size of one part.
	maxPartSize = 5 << 30 // 5 GiB
)

// maxCompleteBody bounds the CompleteMultipartUpload document. 10000 parts at
// the longest possible PartNumber/ETag is a few megabytes; the cap keeps a
// hostile client from streaming an unbounded document into the XML decoder.
const maxCompleteBody = 8 << 20

// Multipart write-limit errors. They are wrapped by the spool and publish
// paths so the handler can answer 413/400 instead of collapsing a client limit
// into an internal error.
var (
	errPartTooLarge = errors.New("multipart part exceeds the S3 part size limit")
	errSessionFull  = errors.New("multipart session exceeds its spool budget")
	errTooManyParts = errors.New("multipart upload exceeds the S3 part count limit")
)

// MultipartConfig parameterises the gateway's multipart spool.
type MultipartConfig = sessions.MultipartConfig

// Defaults applied to a zero-valued MultipartConfig.
var (
	DefaultMultipartDir         = sessions.DefaultMultipartDir
	DefaultMultipartTTL         = sessions.DefaultMultipartTTL
	DefaultMultipartMaxSessions = sessions.DefaultMultipartMaxSessions
)

// --- wire shapes -----------------------------------------------------------

const s3XMLNS = `xmlns="http://s3.amazonaws.com/doc/2006-03-01/"`

type initiateResult struct {
	XMLName  xml.Name `xml:"InitiateMultipartUploadResult"`
	XMLNS    string   `xml:"xmlns,attr"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	UploadID string   `xml:"UploadId"`
}

type completeResult struct {
	XMLName  xml.Name `xml:"CompleteMultipartUploadResult"`
	XMLNS    string   `xml:"xmlns,attr"`
	Location string   `xml:"Location"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	ETag     string   `xml:"ETag"`
}

type partXML struct {
	PartNumber int32  `xml:"PartNumber"`
	ETag       string `xml:"ETag"`
	Size       int64  `xml:"Size"`
}

type listPartsResult struct {
	XMLName        xml.Name  `xml:"ListPartsResult"`
	XMLNS          string    `xml:"xmlns,attr"`
	Bucket         string    `xml:"Bucket"`
	Key            string    `xml:"Key"`
	UploadID       string    `xml:"UploadId"`
	StorageClass   string    `xml:"StorageClass"`
	PartNumberMark int32     `xml:"PartNumberMarker"`
	MaxParts       int32     `xml:"MaxParts"`
	IsTruncated    bool      `xml:"IsTruncated"`
	Parts          []partXML `xml:"Part"`
}

type completeRequest struct {
	XMLName xml.Name  `xml:"CompleteMultipartUpload"`
	Parts   []partXML `xml:"Part"`
}

func (a *API) handleCreateMultipartUpload(w http.ResponseWriter, r *http.Request, sc *scope, bucket, clientKey string, prin port.Principal) {
	const op = "create_multipart"
	// Compute the backend key up front: it both applies the keying rule
	// PutObject applies (rejecting a traversing key) and binds the session to
	// this object, so a later part cannot be attached to a different key.
	backendKey, err := sc.backendKey(bucket, clientKey)
	if err != nil {
		a.metric(op, "error")
		s3err.WriteError(w, r, s3err.InvalidBucketName, "invalid object key")

		return
	}

	profileFP, err := sc.cacheFingerprint(r.Context())
	if err != nil {
		a.metric(op, "error")
		a.log.ErrorContext(r.Context(), "s3 multipart profile",
			slog.String("op", "s3."+op),
			slog.String("err", err.Error()),
		)
		s3err.WriteError(w, r, s3err.InternalError, "")

		return
	}

	s, err := a.mpSess.CreateForUser(
		prin.AccessKeyID,
		sc.principal.User.ID,
		sc.clientPath(bucket, clientKey),
		sc.principal.User.Prefix,
		profileFP,
		sc.targetFingerprint(),
		backendKey,
	)
	if err != nil {
		a.metric(op, "error")
		a.log.ErrorContext(r.Context(), "s3 multipart create",
			slog.String("op", "s3."+op),
			slog.String("err", err.Error()),
		)
		s3err.WriteError(w, r, s3err.InternalError, "")

		return
	}

	a.writeXML(w, r, op, initiateResult{
		XMLNS:    s3XMLNS,
		Bucket:   bucket,
		Key:      clientKey,
		UploadID: s.UploadID,
	})
}

func (a *API) handleUploadPart(w http.ResponseWriter, r *http.Request, vr *awsig.V4VerifiedRequest[port.Principal],
	sc *scope, bucket, clientKey string, prin port.Principal,
) {
	const op = "upload_part"

	q := r.URL.Query()

	s, ok := a.lookupSessionForWrite(w, r, op, sc, bucket, clientKey, prin, q.Get("uploadId"))
	if !ok {
		return
	}

	number, err := strconv.Atoi(q.Get("partNumber"))
	if err != nil || number < 1 || number > maxParts {
		a.metric(op, "error")
		s3err.WriteError(w, r, s3err.InvalidRequest,
			fmt.Sprintf("partNumber must be an integer in 1..%d, got %q", maxParts, q.Get("partNumber")))

		return
	}

	body, err := vr.Reader()
	if err != nil {
		a.writeAuthError(w, r, port.S3OpUploadPart, err)
		return
	}

	etag, err := a.spoolPart(s, number, body)
	if err != nil {
		a.metric(op, "error")
		a.log.ErrorContext(r.Context(), "s3 multipart upload part",
			slog.String("op", "s3."+op),
			slog.Int("part", number),
			slog.String("err", err.Error()),
		)

		switch {
		case bodyTooLarge(err), errors.Is(err, errPartTooLarge), errors.Is(err, errSessionFull):
			s3err.WriteError(w, r, s3err.EntityTooLarge, "")
		case errors.Is(err, errTooManyParts):
			s3err.WriteError(w, r, s3err.InvalidRequest, err.Error())
		default:
			s3err.WriteError(w, r, s3err.InternalError, "")
		}

		return
	}

	w.Header().Set("ETag", etag)
	w.Header().Set("x-amz-request-id", s3err.RequestID(r))
	w.WriteHeader(http.StatusOK)
	a.metric(op, "ok")
}

// spoolPart streams one part into the session directory and publishes it.
// Limits are enforced around the write, not after it: a part that pushes the
// session past its byte budget is removed again rather than left for the
// sweeper, so an over-quota client cannot fill the disk by ignoring the error.
//
// The body goes to a fresh temp file, never to the part's own path: a re-upload
// of a number replaces the old part by rename only once the replacement is
// complete and has passed its checks. S3 drops the old part when the new one
// succeeds, not when it starts, so a retry that fails half-way (dropped
// connection, cancelled request, signature error) must leave the accepted bytes
// and their record exactly as they were.
func (a *API) spoolPart(s *sessions.Session, number int, body io.Reader) (string, error) {
	// Stamped before the body is consumed, not only by publishPart at the end. A
	// session carries the stamp of its CreateMultipartUpload (or of its last
	// finished part) for the whole of a slow write, so a sweeper running in
	// between would treat a live upload as idle: it drops the session and
	// RemoveAlls the directory out from under the open file, and the client is
	// told 200 with an ETag for bytes that have just been deleted, only to get
	// NoSuchUpload on Complete. An upload in progress is not an idle session,
	// whichever side of the write we happen to be on.
	s.Touch()

	// The part number was validated against 1..maxParts by the caller and is
	// formatted as %05d, so it cannot escape session.dir. gosec's taint analysis
	// cannot see either fact, hence the directives.
	path := s.PartPath(number)

	// A unique name rather than path+".new": two concurrent UploadPart calls for
	// the same number would otherwise truncate each other's spool and publish a
	// mixture. CreateTemp creates it 0600 in the session directory.
	tmp, err := os.CreateTemp(s.Dir, fmt.Sprintf("part-%05d-new-*", number))
	if err != nil {
		return "", err
	}

	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		// A no-op once the file has been renamed into place.
		_ = os.Remove(tmpPath) //nolint:gosec // tmpPath is the file os.CreateTemp just made in session.dir
	}()

	h := md5.New() //nolint:gosec // S3 defines the part ETag as the MD5 of the part

	n, err := spoolTo(tmp, body, h)
	if err != nil {
		return "", err
	}

	if n > maxPartSize {
		return "", fmt.Errorf("%w: part %d is %d bytes, over the %d byte S3 part limit",
			errPartTooLarge, number, n, int64(maxPartSize))
	}

	// No fsync: a part is process state until it is assembled, and a crash loses
	// the upload anyway (the client retries), so flushing a multi-gigabyte part
	// to stable storage buys nothing but latency.
	//
	// Closed before the rename so the publish works on platforms that cannot
	// rename a file that is still open (Windows), and so a deferred flush error
	// cannot be lost.
	if err := tmp.Close(); err != nil {
		return "", err
	}

	etag := `"` + hex.EncodeToString(h.Sum(nil)) + `"`
	if err := a.publishPart(s, number, tmpPath, path, n, etag); err != nil {
		return "", err
	}

	return etag, nil
}

// publishPart makes a fully written temp file the part for number: it checks the
// session's limits, renames the file into place and records size and ETag, all
// under the session lock.
//
// The order is the contract. The limits are checked before the rename, so a part
// refused by the budget leaves the previous one untouched; and the rename is
// atomic, so a reader (Complete's assembly, which runs outside this lock) sees
// either the old bytes or the new ones, never a mixture. Two concurrent retries
// of the same number therefore cannot interleave bytes, and the last published
// one is the one that is recorded.
func (a *API) publishPart(s *sessions.Session, number int, srcPath, dstPath string, size int64, etag string) error {
	s.Mu.Lock()
	defer s.Mu.Unlock()

	_, replacing := s.Parts[number]
	if !replacing && len(s.Parts) >= maxParts {
		return fmt.Errorf("%w: an upload may have at most %d parts", errTooManyParts, maxParts)
	}

	total := s.Bytes - sizeOf(s, number) + size
	if a.mpMaxBytes > 0 && total > a.mpMaxBytes {
		return fmt.Errorf("%w: multipart session would hold %d bytes, over its %d byte spool limit",
			errSessionFull, total, a.mpMaxBytes)
	}

	//nolint:gosec // G703: dstPath is session.partPath(number), validated by the caller
	if err := os.Rename(srcPath, dstPath); err != nil {
		return err
	}

	s.Parts[number] = sessions.Part{Path: dstPath, Size: size, ETag: etag}
	s.Bytes = total
	s.TouchedAt = time.Now()

	return nil
}

// sizeOf returns the recorded size of a part, or 0. Caller holds s.Mu.
func sizeOf(s *sessions.Session, number int) int64 {
	if p, ok := s.Parts[number]; ok {
		return p.Size
	}

	return 0
}

// parseCompleteBody decodes the completion document's part list.
//
// io.EOF is success with an empty list, not a parse failure: aws-cli sends an
// empty body when --multipart-upload is omitted, and S3 reads that as "assemble
// from every part you uploaded". The body is bounded, so a client cannot stream
// an unbounded document into the decoder.
func parseCompleteBody(r io.Reader) ([]partXML, error) {
	src := bufio.NewReader(io.LimitReader(r, maxCompleteBody))
	// An empty body and a body of plain text both end in io.EOF from the
	// decoder, but they mean opposite things: "no part list" and "not XML". Skip
	// leading whitespace to tell them apart without buffering the document.
	for {
		b, err := src.Peek(1)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, nil
			}

			return nil, err
		}

		if !isXMLSpace(b[0]) {
			break
		}

		_, _ = src.ReadByte()
	}

	var req completeRequest
	if err := xml.NewDecoder(src).Decode(&req); err != nil {
		return nil, err
	}

	// Go's decoder rejects a wrong root name only because XMLName names one.
	// Keeping the check explicit is what turns "this is not XML" into
	// MalformedXML instead of quietly reading as "no part list", which would
	// complete the upload from every part the client happened to send.
	if req.XMLName.Local != "CompleteMultipartUpload" {
		return nil, fmt.Errorf("root element is %q, want CompleteMultipartUpload", req.XMLName.Local)
	}

	return req.Parts, nil
}

// isXMLSpace reports whether b is XML whitespace, i.e. ignorable before the
// root element.
func isXMLSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\r' || b == '\n'
}

// listedParts returns every uploaded part as a completion entry, in ascending
// order. It is what an empty CompleteMultipartUpload body resolves to: S3 builds
// the object from every part that was uploaded, and a client that omits the list
// means exactly that. Passing the result back through resolveParts keeps one code
// path for validation, so the ETag and ordering checks are not bypassed.
func listedParts(s *sessions.Session) []partXML {
	s.Mu.Lock()
	defer s.Mu.Unlock()

	nums := s.PartNumbers()
	out := make([]partXML, 0, len(nums))

	for _, n := range nums {
		out = append(out, partXML{PartNumber: wirePartNumber(n), ETag: s.Parts[n].ETag, Size: s.Parts[n].Size})
	}

	return out
}

func (a *API) handleCompleteMultipartUpload(w http.ResponseWriter, r *http.Request, vr *awsig.V4VerifiedRequest[port.Principal],
	sc *scope, bucket, clientKey string, prin port.Principal,
) {
	const op = "complete_multipart"

	s, ok := a.lookupSessionForWrite(w, r, op, sc, bucket, clientKey, prin, r.URL.Query().Get("uploadId"))
	if !ok {
		return
	}

	arch, err := sc.archiveFor(r.Context())
	if err != nil {
		a.metric(op, "error")
		a.log.ErrorContext(r.Context(), "s3 multipart profile",
			slog.String("op", "s3."+op),
			slog.String("err", err.Error()),
		)
		s3err.WriteError(w, r, s3err.InternalError, "")

		return
	}

	body, err := vr.Reader()
	if err != nil {
		a.writeAuthError(w, r, port.S3OpCompleteMultipartUpload, err)
		return
	}

	listed, err := parseCompleteBody(body)
	if err != nil {
		a.metric(op, "error")
		s3err.WriteError(w, r, s3err.MalformedXML, "could not parse CompleteMultipartUpload: "+err.Error())

		return
	}

	// An empty body means "no part list", which is what aws-cli sends when
	// --multipart-upload is omitted. S3 assembles from every uploaded part in that
	// case, so the session supplies them; see session.listedParts.
	if len(listed) == 0 {
		listed = listedParts(s)
	}

	if len(listed) == 0 {
		a.metric(op, "error")
		s3err.WriteError(w, r, s3err.InvalidRequest, "CompleteMultipartUpload for an upload with no parts")

		return
	}

	parts, code, msg := resolveParts(s, listed)
	if code != "" {
		a.metric(op, "error")
		s3err.WriteError(w, r, code, msg)

		return
	}

	// Assemble inside the session directory, on the same filesystem as the
	// parts, so the whole upload disappears with one RemoveAll. Disk use peaks
	// at roughly twice the object: parts plus the assembled copy
	// (docs/multipart.md §8).
	assembled, size, sum, err := assembleParts(s.Dir, parts)
	if err != nil {
		a.metric(op, "error")
		a.log.ErrorContext(r.Context(), "s3 multipart assemble",
			slog.String("op", "s3."+op),
			slog.String("err", err.Error()),
		)
		s3err.WriteError(w, r, s3err.InternalError, "")

		return
	}
	// Deferred, not immediate: a failure below must not destroy data the client
	// would otherwise only have to re-read. The successful path removes the
	// session, and with it this file, a moment later.
	defer func() { _ = os.Remove(assembled) }()

	_, action, err := arch.UploadFile(r.Context(), domain.FileInfo{
		AbsPath: assembled,
		RelPath: filepath.Base(assembled),
		Size:    size,
		ModTime: time.Now().UTC(),
	}, service.ArchiveOptions{
		Root:        s.Dir,
		ExplicitKey: s.ClientKey,
		Op:          "upload",
		// The digest of the assembled stream, so Archive does not hash the file
		// a second time. At encryption.mode=none this is also what the store
		// records as the object identity (domain.PutMeta).
		PlaintextSHA256: sum,
	})
	if err != nil {
		a.metric(op, "error")
		a.log.ErrorContext(r.Context(), "s3 multipart upload",
			slog.String("op", "s3."+op),
			slog.String("err", err.Error()),
		)
		s3err.WriteError(w, r, s3err.InternalError, "")

		return
	}

	a.mpSess.Drop(s)

	if action == identity.ActionUpload {
		// The gateway wrote a new version, so any cached plaintext entry
		// describes the previous one — the same reason handlePut invalidates.
		sc.invalidateCache(r.Context(), s.BackendKey, "s3."+op)
	}

	// ETag is sha256(plaintext) in quotes, exactly as handleGet and handlePut
	// report it — not the S3 multipart form (md5-of-md5s with a -N suffix). This
	// facade's ETag is the object identity everywhere else, and a client that
	// saw two schemes for the same object could not use either.
	a.writeXML(w, r, op, completeResult{
		XMLNS:    s3XMLNS,
		Location: objectLocation(r, bucket, clientKey),
		Bucket:   bucket,
		Key:      clientKey,
		ETag:     `"` + sum + `"`,
	})
}

// resolveParts checks the client's part list against what was actually written
// and returns the parts to concatenate, in the order the client asked for.
//
// Every listed number must have been uploaded, the numbers must be strictly
// ascending (S3 requires it, and the SDK sorts before sending), and a supplied
// ETag must match. The ETag check is best effort in the sense that a client that
// omits it is accepted — not every S3 client sends one back.
//
// A part that was uploaded but not listed is *not* an error: S3 assembles the
// object from the listed parts and discards the rest, and a facade that
// answered InvalidPart would reject a client that real S3 accepts. The SDK
// uploader guards its own part count before completing (manager's expectParts
// check), so the truncation this permits is not reachable through it.
func resolveParts(s *sessions.Session, want []partXML) ([]sessions.Part, s3err.Code, string) {
	s.Mu.Lock()
	defer s.Mu.Unlock()

	if len(want) > maxParts {
		return nil, s3err.InvalidRequest, fmt.Sprintf("an upload may have at most %d parts, %d were listed", maxParts, len(want))
	}

	prev := int32(0)

	out := make([]sessions.Part, 0, len(want))
	for i, wp := range want {
		if wp.PartNumber <= prev {
			return nil, s3err.InvalidPartOrder, fmt.Sprintf(
				"part %d (number %d) does not follow part number %d; parts must be listed in ascending order", i+1, wp.PartNumber, prev,
			)
		}

		prev = wp.PartNumber

		p, ok := s.Parts[int(wp.PartNumber)]
		if !ok {
			return nil, s3err.InvalidPart, fmt.Sprintf("part %d was never uploaded to this upload", wp.PartNumber)
		}

		if want := strings.Trim(wp.ETag, `"`); want != "" && !strings.EqualFold(want, strings.Trim(p.ETag, `"`)) {
			return nil, s3err.InvalidPart, fmt.Sprintf("part %d was uploaded with ETag %s, the completion list says %q",
				wp.PartNumber, p.ETag, wp.ETag)
		}
		// Every part but the last must reach the S3 minimum. A shorter one means
		// the client's part size is wrong, and accepting it would write an object
		// no other S3 client could reproduce.
		if i < len(want)-1 && p.Size < minPartSize {
			return nil, s3err.EntityTooSmall, fmt.Sprintf(
				"part %d is %d bytes; every part except the last must be at least %d bytes", wp.PartNumber, p.Size, int64(minPartSize),
			)
		}

		out = append(out, p)
	}

	return out, "", ""
}

// assembleParts concatenates parts into a new file in dir and returns its path,
// size and the SHA-256 of the plaintext stream. Hashing as the bytes go by is
// what lets Complete hand the digest to ArchiveOptions.PlaintextSHA256 instead
// of making Archive hash the file again.
//
// Every part is checked against the record resolveParts validated — size and MD5
// — as it is copied. That validation happens under the session lock and assembly
// deliberately does not (a long Complete must not block the registry, see
// session), so between the two a concurrent UploadPart can re-open a part's path
// with O_TRUNC and rewrite it. Copying the replacement unchecked would assemble
// content the client never listed, answer 200 with its digest, and can produce an
// object whose non-final part is under the S3 minimum that resolveParts just
// enforced. Failing here turns that into a clean error instead.
func assembleParts(dir string, parts []sessions.Part) (string, int64, string, error) {
	f, err := os.CreateTemp(dir, "assembled-*")
	if err != nil {
		return "", 0, "", err
	}

	path := f.Name()

	cleanup := func(err error) (string, int64, string, error) {
		_ = f.Close()
		_ = os.Remove(path)

		return "", 0, "", err
	}
	if err := f.Chmod(0o600); err != nil {
		return cleanup(err)
	}

	h := sha256.New()

	var total int64

	for i, p := range parts {
		src, err := os.Open(p.Path)
		if err != nil {
			return cleanup(err)
		}

		// The MD5 is of the part alone, so it needs its own hash: h carries the
		// running SHA-256 of everything assembled so far.
		md5Sum := md5.New() //nolint:gosec // S3 defines the part ETag as the MD5 of the part bytes
		n, err := spoolTo(f, src, h, md5Sum)
		_ = src.Close()

		if err != nil {
			return cleanup(err)
		}

		if n != p.Size {
			return cleanup(fmt.Errorf("part %d is %d bytes on disk, %d bytes were uploaded and validated",
				i+1, n, p.Size))
		}

		if got := hex.EncodeToString(md5Sum.Sum(nil)); !strings.EqualFold(got, strings.Trim(p.ETag, `"`)) {
			return cleanup(fmt.Errorf("part %d hashes to %s on disk, it was uploaded as %s",
				i+1, got, strings.Trim(p.ETag, `"`)))
		}

		total += n
	}

	// No fsync: the assembled file is consumed by the upload that follows in
	// this same request and removed with the session, so it only has to be
	// visible to this process.
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return "", 0, "", err
	}

	return path, total, hex.EncodeToString(h.Sum(nil)), nil
}

func (a *API) handleAbortMultipartUpload(w http.ResponseWriter, r *http.Request, sc *scope, bucket, clientKey string, prin port.Principal) {
	const op = "abort_multipart"

	s, ok := a.lookupSessionForOwner(w, r, op, sc, bucket, clientKey, prin, r.URL.Query().Get("uploadId"))
	if !ok {
		return
	}

	a.mpSess.Drop(s)
	w.Header().Set("x-amz-request-id", s3err.RequestID(r))
	w.WriteHeader(http.StatusNoContent)
	a.metric(op, "ok")
}

// handleListParts answers the part inventory of a live upload. The AWS SDK in
// use here never calls it, but it is part of the multipart API and a client
// that resumes by asking is better served than by a 405.
func (a *API) handleListParts(w http.ResponseWriter, r *http.Request, sc *scope, bucket, clientKey string, prin port.Principal) {
	const op = "list_parts"

	s, ok := a.lookupSessionForOwner(w, r, op, sc, bucket, clientKey, prin, r.URL.Query().Get("uploadId"))
	if !ok {
		return
	}

	s.Mu.Lock()
	nums := s.PartNumbers()

	out := listPartsResult{
		XMLNS:        s3XMLNS,
		Bucket:       bucket,
		Key:          clientKey,
		UploadID:     s.UploadID,
		StorageClass: "STANDARD",
		MaxParts:     maxParts,
		Parts:        make([]partXML, 0, len(nums)),
	}
	for _, n := range nums {
		p := s.Parts[n]
		out.Parts = append(out.Parts, partXML{PartNumber: wirePartNumber(n), ETag: p.ETag, Size: p.Size})
	}
	s.Mu.Unlock()
	a.writeXML(w, r, op, out)
}

// wirePartNumber narrows a stored part number to the wire type. Every number in
// a session was checked against 1..maxParts before it was recorded, so the
// conversion cannot lose anything; it is written out rather than asserted
// because nothing at the call site would make the reader believe that.
func wirePartNumber(n int) int32 {
	if n < 1 || n > maxParts {
		return 0
	}

	return int32(n)
}

// lookupSessionForWrite resolves an upload id for UploadPart/Complete. In
// addition to ownership it checks that the user's current prefix and profile
// still match the snapshot taken at CreateMultipartUpload: changing either
// mid-upload makes Complete reject with NoSuchUpload rather than write an
// object under the old policy.
func (a *API) lookupSessionForWrite(w http.ResponseWriter, r *http.Request, op string,
	sc *scope, bucket, clientKey string, prin port.Principal, uploadID string,
) (*sessions.Session, bool) {
	if uploadID == "" {
		a.metric(op, "error")
		s3err.WriteError(w, r, s3err.InvalidRequest, "uploadId is required")

		return nil, false
	}

	backendKey, err := sc.backendKey(bucket, clientKey)
	if err != nil {
		a.metric(op, "error")
		s3err.WriteError(w, r, s3err.InvalidBucketName, "invalid object key")

		return nil, false
	}

	profileFP, err := sc.cacheFingerprint(r.Context())
	if err != nil {
		a.metric(op, "error")
		a.log.ErrorContext(r.Context(), "s3 multipart profile",
			slog.String("op", "s3."+op),
			slog.String("err", err.Error()),
		)
		s3err.WriteError(w, r, s3err.InternalError, "")

		return nil, false
	}

	s, err := a.mpSess.GetForWrite(
		uploadID,
		prin.AccessKeyID,
		sc.clientPath(bucket, clientKey),
		backendKey,
		sc.principal.User.ID,
		sc.principal.User.Prefix,
		profileFP,
		sc.targetFingerprint(),
	)

	return a.sessionResult(w, r, op, prin, s, err)
}

// lookupSessionForOwner resolves an upload id for Abort/ListParts. It binds only
// the access key and the client key, so an upload can still be aborted after its
// prefix or profile changed. The id is a bearer token; no object bytes are read
// or written by these operations.
func (a *API) lookupSessionForOwner(w http.ResponseWriter, r *http.Request, op string,
	sc *scope, bucket, clientKey string, prin port.Principal, uploadID string,
) (*sessions.Session, bool) {
	if uploadID == "" {
		a.metric(op, "error")
		s3err.WriteError(w, r, s3err.InvalidRequest, "uploadId is required")

		return nil, false
	}

	s, err := a.mpSess.GetForOwner(uploadID, prin.AccessKeyID, sc.clientPath(bucket, clientKey))

	return a.sessionResult(w, r, op, prin, s, err)
}

func (a *API) sessionResult(w http.ResponseWriter, r *http.Request, op string,
	prin port.Principal, s *sessions.Session, err error,
) (*sessions.Session, bool) {
	switch {
	case errors.Is(err, os.ErrNotExist):
		a.metric(op, "error")
		s3err.WriteError(w, r, s3err.NoSuchUpload, "")

		return nil, false
	case errors.Is(err, sessions.ErrForeignUpload):
		a.metric(op, "denied")
		a.log.WarnContext(r.Context(), "s3 multipart upload id is not yours",
			slog.String("op", "s3."+op),
			slog.String("access_key_id", prin.AccessKeyID),
		)
		s3err.WriteError(w, r, s3err.NoSuchUpload, "")

		return nil, false
	case err != nil:
		a.metric(op, "error")
		s3err.WriteError(w, r, s3err.InternalError, "")

		return nil, false
	}

	return s, true
}

// objectLocation is the path-style URL of the completed object, for the
// Location element of CompleteMultipartUploadResult.
func objectLocation(r *http.Request, bucket, key string) string {
	u := *r.URL
	u.RawQuery = ""
	u.Path = "/" + bucket + "/" + key

	return u.String()
}

// --- sweeper ---------------------------------------------------------------

// SweepExpired drops multipart sessions idle for longer than the configured
// TTL, plus any over the session limit, and returns how many were removed.
func (a *API) SweepExpired() int {
	if a.mpSess == nil {
		return 0
	}

	return a.mpSess.SweepExpired(a.mpTTL, a.mpMaxSessions)
}

// StartSweeper runs the multipart and spool sweepers on an interval until ctx
// is cancelled; the first sweep runs immediately. A non-positive interval
// disables the loop.
//
// Without it an interrupted upload keeps its bytes on disk forever, and a
// request that died between creating and removing a spool file leaves client
// plaintext behind: nothing else in s3vault owns either directory. That makes
// this part of the work rather than an option.
func (a *API) StartSweeper(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		return
	}

	go func() {
		run := func() {
			if n := a.SweepExpired(); n > 0 {
				a.log.InfoContext(ctx, "s3 multipart sweep",
					slog.String("op", "s3.multipart"),
					slog.Int("removed", n),
				)
			}

			if n := a.SweepSpool(a.spoolTTL); n > 0 {
				a.log.InfoContext(ctx, "s3 spool sweep",
					slog.String("op", "s3.spool"),
					slog.String("dir", a.spoolDir),
					slog.Int("removed", n),
				)
			}
		}
		run()

		t := time.NewTicker(interval)
		defer t.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				run()
			}
		}
	}()
}

// SweepSpool removes spool files older than ttl and returns how many it removed.
func (a *API) SweepSpool(ttl time.Duration) int {
	return spool.Sweep(a.spoolDir, ttl)
}
