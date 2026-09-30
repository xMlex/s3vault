package s3api

import (
	"bufio"
	"context"
	"crypto/md5" //nolint:gosec // S3 defines the part ETag as the MD5 of the part bytes
	"crypto/rand"
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
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/amwolff/awsig"

	"github.com/xMlex/s3vault/internal/domain"
	"github.com/xMlex/s3vault/internal/identity"
	"github.com/xMlex/s3vault/internal/port"
	"github.com/xMlex/s3vault/internal/s3api/s3err"
	"github.com/xMlex/s3vault/internal/service"
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

// MultipartConfig parameterises the gateway's multipart spool.
type MultipartConfig struct {
	// Dir is the spool root; each session gets a subdirectory of it. It is
	// deliberately NOT cache.dir: the cache has its own invariants (TTL,
	// sweeper, lockfile) and is off by default, while multipart must work always.
	// Empty falls back to DefaultMultipartDir, which is what the CLI avoids by
	// passing server.multipart_dir.
	Dir string
	// TTL is how long a session may sit untouched before the sweeper drops it
	// and its files. TouchedAt is bumped on every UploadPart, so a long upload
	// in progress is not evicted mid-flight. Zero means DefaultMultipartTTL.
	TTL time.Duration
	// SweepInterval is how often the sweeper runs. Zero disables the loop;
	// lazy expiry on access still applies.
	SweepInterval time.Duration
	// MaxSessions bounds live sessions, each of which holds real bytes on disk.
	// Zero means DefaultMultipartMaxSessions.
	MaxSessions int
	// MaxBytes bounds one session's spooled parts. Zero means unlimited.
	MaxBytes int64
}

// Defaults applied to a zero-valued MultipartConfig.
var (
	DefaultMultipartDir         = filepath.Join(os.TempDir(), "s3vault-multipart")
	DefaultMultipartTTL         = 24 * time.Hour
	DefaultMultipartMaxSessions = 64
)

// part is one uploaded part: a file in the session directory plus what
// CompleteMultipartUpload needs to verify it and assemble it.
type part struct {
	path string // file in the session's spool directory
	size int64
	etag string // MD5 hex, quoted — the value returned to the client
}

// session is one in-flight multipart upload.
//
// mu guards parts, bytes and touchedAt. It is needed even though each part is a
// separate file and so never conflicts on disk: the AWS SDK sends five
// UploadPart requests at once, and a concurrent map write is a crash, not a race
// report. A lock per session, rather than one for the whole registry, is what
// keeps a Complete — which holds the session for the length of the whole
// assembly — from blocking the UploadPart of an unrelated upload.
type session struct {
	mu sync.Mutex

	uploadID    string
	backendKey  string
	accessKeyID string
	createdAt   time.Time
	touchedAt   time.Time
	parts       map[int]part
	dir         string
	bytes       int64
}

// partPath is the on-disk name of a part. The number is the file name, so
// re-uploading a part replaces it — as in S3.
func (s *session) partPath(number int) string {
	return filepath.Join(s.dir, fmt.Sprintf("part-%05d", number))
}

// partNumbers returns the uploaded part numbers in ascending order.
func (s *session) partNumbers() []int {
	nums := make([]int, 0, len(s.parts))
	for n := range s.parts {
		nums = append(nums, n)
	}

	slices.Sort(nums)

	return nums
}

// mpRegistry holds the live multipart sessions of one process.
//
// Sessions do not survive a restart: the registry is in memory and the spool
// root is wiped when it is opened, so an interrupted upload leaves nothing for
// the next process to half-adopt. That is a deliberate limit (docs/multipart.md
// §8), and wiping at open is what keeps it from turning into a slow disk leak.
type mpRegistry struct {
	mu       sync.Mutex
	dir      string
	sessions map[string]*session
	log      *slog.Logger
}

// newMPRegistry prepares the spool root and returns an empty registry.
func newMPRegistry(cfg MultipartConfig, log *slog.Logger) (*mpRegistry, error) {
	dir, err := filepath.Abs(cfg.Dir)
	if err != nil {
		return nil, fmt.Errorf("multipart spool dir: %w", err)
	}
	// A session belongs to the process that created it, so anything already in
	// the spool root belongs to a process that is gone. The local object store
	// gives .s3vault-tmp the same treatment, and a failure here is fatal rather
	// than logged: a spool dir we cannot trust is a spool dir we must not use.
	if err := os.RemoveAll(dir); err != nil {
		return nil, fmt.Errorf("multipart spool dir %s: %w", dir, err)
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("multipart spool dir %s: %w", dir, err)
	}

	return &mpRegistry{dir: dir, sessions: map[string]*session{}, log: log}, nil
}

// create registers a new session and returns it.
func (reg *mpRegistry) create(accessKeyID, backendKey string) (*session, error) {
	uploadID, err := newUploadID()
	if err != nil {
		return nil, err
	}

	dir, err := os.MkdirTemp(reg.dir, "mput-")
	if err != nil {
		return nil, fmt.Errorf("multipart session dir: %w", err)
	}

	now := time.Now()
	s := &session{
		uploadID:    uploadID,
		backendKey:  backendKey,
		accessKeyID: accessKeyID,
		createdAt:   now,
		touchedAt:   now,
		parts:       map[int]part{},
		dir:         dir,
	}

	reg.mu.Lock()
	defer reg.mu.Unlock()

	reg.sessions[uploadID] = s

	return s, nil
}

// newUploadID returns a 256-bit random identifier.
//
// It is also the bearer token for the spooled bytes: whoever holds the id can
// append parts to that upload. It therefore comes from crypto/rand — never a
// counter, a timestamp, or a hash of the object key.
func newUploadID() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("upload id: %w", err)
	}

	return hex.EncodeToString(b[:]), nil
}

// errForeignUpload is returned when a principal addresses a session it did not
// create. On the wire it is indistinguishable from "no such upload" — both
// answer NoSuchUpload — so the id cannot be probed for existence; the log line
// is where the real reason survives.
var errForeignUpload = errors.New("upload id belongs to another principal")

// get looks a session up and enforces that the caller owns it.
//
// Binding to AccessKeyID *and* to backendKey is the reason a session is not just
// a random id: otherwise any authenticated client could append parts to
// somebody else's object, and the Complete would assemble a file the original
// uploader never wrote.
func (reg *mpRegistry) get(uploadID, accessKeyID, backendKey string) (*session, error) {
	reg.mu.Lock()
	s, ok := reg.sessions[uploadID]
	reg.mu.Unlock()

	if !ok {
		return nil, os.ErrNotExist
	}

	if s.accessKeyID != accessKeyID || s.backendKey != backendKey {
		return nil, errForeignUpload
	}

	return s, nil
}

// drop unregisters a session and removes its files. Safe to call twice.
func (reg *mpRegistry) drop(s *session) {
	reg.mu.Lock()
	delete(reg.sessions, s.uploadID)
	reg.mu.Unlock()
	reg.remove(s)
}

func (reg *mpRegistry) remove(s *session) {
	//nolint:gosec // G703: s.dir is os.MkdirTemp output under the configured spool root, never request data
	if err := os.RemoveAll(s.dir); err != nil {
		reg.log.Warn("s3 multipart session cleanup",
			slog.String("op", "s3.multipart"),
			slog.String("err", err.Error()),
		)
	}
}

// sweepExpired drops sessions untouched for longer than ttl, plus any over
// maxSessions, and returns how many it removed. It is the only thing that
// reclaims the spool after an interrupted upload: no other timer in s3vault
// would notice.
func (reg *mpRegistry) sweepExpired(ttl time.Duration, maxSessions int) int {
	return reg.sweepExpiredAt(ttl, maxSessions, time.Now())
}

func (reg *mpRegistry) sweepExpiredAt(ttl time.Duration, maxSessions int, now time.Time) int {
	// Collect under the registry lock, delete files outside it: RemoveAll can
	// block on I/O and the registry lock is on the path of every UploadPart.
	reg.mu.Lock()
	// Snapshot (session, touchedAt) pairs under both locks: sorting by activity
	// while a concurrent UploadPart is bumping touchedAt would otherwise race.
	type aged struct {
		s       *session
		touched time.Time
	}

	live := make([]aged, 0, len(reg.sessions))

	var expired []*session

	for id, s := range reg.sessions {
		s.mu.Lock()
		touched := s.touchedAt
		s.mu.Unlock()

		if now.Sub(touched) >= ttl {
			delete(reg.sessions, id)

			expired = append(expired, s)

			continue
		}

		live = append(live, aged{s: s, touched: touched})
	}
	// Over the limit: the least recently touched goes first, because spool
	// space is the resource being protected, not the session count.
	if over := len(live) - maxSessions; over > 0 {
		slices.SortFunc(live, func(x, y aged) int { return x.touched.Compare(y.touched) })

		for i := 0; i < over && i < len(live); i++ {
			delete(reg.sessions, live[i].s.uploadID)
			expired = append(expired, live[i].s)
		}
	}
	reg.mu.Unlock()

	for _, s := range expired {
		reg.remove(s)
	}

	return len(expired)
}

// count reports the number of live sessions.
func (reg *mpRegistry) count() int {
	reg.mu.Lock()
	defer reg.mu.Unlock()

	return len(reg.sessions)
}

// --- wire shapes -----------------------------------------------------------

// s3XMLNS is the S3 XML namespace. The SDK matches response roots by local
// name, and every other document this facade writes carries it, so multipart
// answers are no different from the rest of the surface.
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

// completeRequest is the body of CompleteMultipartUpload. Only the part list is
// read; the other members S3 accepts are ignored rather than rejected, so a
// stricter client is not turned away for decoration.
type completeRequest struct {
	XMLName xml.Name  `xml:"CompleteMultipartUpload"`
	Parts   []partXML `xml:"Part"`
}

// --- handlers --------------------------------------------------------------

func (a *API) handleCreateMultipartUpload(w http.ResponseWriter, r *http.Request, bucket, clientKey string, prin port.Principal) {
	const op = "create_multipart"
	// Compute the backend key up front: it both applies the keying rule
	// PutObject applies (rejecting a traversing key) and binds the session to
	// this object, so a later part cannot be attached to a different key.
	backendKey, err := a.backendKey(bucket, clientKey)
	if err != nil {
		a.metric(op, "error")
		s3err.WriteError(w, r, s3err.InvalidBucketName, "invalid object key")

		return
	}

	s, err := a.mp.create(prin.AccessKeyID, backendKey)
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
		UploadID: s.uploadID,
	})
}

func (a *API) handleUploadPart(w http.ResponseWriter, r *http.Request, vr *awsig.V4VerifiedRequest[port.Principal],
	bucket, clientKey string, prin port.Principal,
) {
	const op = "upload_part"

	q := r.URL.Query()

	s, ok := a.lookupSession(w, r, op, bucket, clientKey, prin, q.Get("uploadId"))
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
		s3err.WriteError(w, r, s3err.InternalError, "")

		return
	}

	w.Header().Set("ETag", etag)
	w.Header().Set("x-amz-request-id", s3err.RequestID(r))
	w.WriteHeader(http.StatusOK)
	a.metric(op, "ok")
}

// spoolPart streams one part into the session directory and records its size and
// MD5. Limits are enforced around the write, not after it: a part that pushes
// the session past its byte budget is removed again rather than left for the
// sweeper, so an over-quota client cannot fill the disk by ignoring the error.
func (a *API) spoolPart(s *session, number int, body io.Reader) (string, error) {
	// Stamped before the body is consumed, not only by recordPart at the end. A
	// session carries the stamp of its CreateMultipartUpload (or of its last
	// finished part) for the whole of a slow write, so a sweeper running in
	// between would treat a live upload as idle: it drops the session and
	// RemoveAlls the directory out from under the open file, and the client is
	// told 200 with an ETag for bytes that have just been deleted, only to get
	// NoSuchUpload on Complete. An upload in progress is not an idle session,
	// whichever side of the write we happen to be on.
	s.touch()

	// The part number was validated against 1..maxParts by the caller and is
	// formatted as %05d, so it cannot escape session.dir. gosec's taint analysis
	// cannot see either fact, hence the directives.
	path := s.partPath(number)
	discard := func() {
		_ = os.Remove(path) //nolint:gosec // G703: path is session.partPath(number), see above
	}
	//nolint:gosec // G304: same as above
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	h := md5.New() //nolint:gosec // S3 defines the part ETag as the MD5 of the part

	n, err := spoolTo(f, body, h)
	if err != nil {
		discard()
		return "", err
	}

	if n > maxPartSize {
		discard()
		return "", fmt.Errorf("part %d is %d bytes, over the %d byte S3 part limit", number, n, int64(maxPartSize))
	}

	if err := f.Sync(); err != nil {
		discard()
		return "", err
	}

	etag := `"` + hex.EncodeToString(h.Sum(nil)) + `"`
	if err := a.recordPart(s, number, path, n, etag); err != nil {
		discard()
		return "", err
	}

	return etag, nil
}

// recordPart publishes a part in the session map, enforcing the per-session
// part count and byte budget.
func (a *API) recordPart(s *session, number int, path string, size int64, etag string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, replacing := s.parts[number]
	if !replacing && len(s.parts) >= maxParts {
		return fmt.Errorf("an upload may have at most %d parts", maxParts)
	}

	total := s.bytes - sizeOf(s, number) + size
	if a.mpMaxBytes > 0 && total > a.mpMaxBytes {
		return fmt.Errorf("multipart session would hold %d bytes, over its %d byte spool limit", total, a.mpMaxBytes)
	}

	s.parts[number] = part{path: path, size: size, etag: etag}
	s.bytes = total
	s.touchedAt = time.Now()

	return nil
}

// sizeOf returns the recorded size of a part, or 0. Caller holds s.mu.
func sizeOf(s *session, number int) int64 {
	if p, ok := s.parts[number]; ok {
		return p.size
	}

	return 0
}

// touch stamps the session as active. It is called at the *start* of a part write
// as well as from recordPart at the end, so the sweeper's notion of idle cannot
// fall inside a write in progress.
func (s *session) touch() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.touchedAt = time.Now()
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
func (s *session) listedParts() []partXML {
	s.mu.Lock()
	defer s.mu.Unlock()

	nums := s.partNumbers()
	out := make([]partXML, 0, len(nums))

	for _, n := range nums {
		out = append(out, partXML{PartNumber: wirePartNumber(n), ETag: s.parts[n].etag, Size: s.parts[n].size})
	}

	return out
}

func (a *API) handleCompleteMultipartUpload(w http.ResponseWriter, r *http.Request, vr *awsig.V4VerifiedRequest[port.Principal],
	bucket, clientKey string, prin port.Principal,
) {
	const op = "complete_multipart"

	s, ok := a.lookupSession(w, r, op, bucket, clientKey, prin, r.URL.Query().Get("uploadId"))
	if !ok {
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
		listed = s.listedParts()
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
	assembled, size, sum, err := assembleParts(s.dir, parts)
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

	_, action, err := a.archive.UploadFile(r.Context(), domain.FileInfo{
		AbsPath: assembled,
		RelPath: filepath.Base(assembled),
		Size:    size,
		ModTime: time.Now().UTC(),
	}, service.ArchiveOptions{
		Root:        s.dir,
		ExplicitKey: a.clientPath(bucket, clientKey),
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

	a.mp.drop(s)

	if action == identity.ActionUpload {
		// The gateway wrote a new version, so any cached plaintext entry
		// describes the previous one — the same reason handlePut invalidates.
		a.invalidateCache(r.Context(), s.backendKey, "s3."+op)
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
func resolveParts(s *session, want []partXML) ([]part, s3err.Code, string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(want) > maxParts {
		return nil, s3err.InvalidRequest, fmt.Sprintf("an upload may have at most %d parts, %d were listed", maxParts, len(want))
	}

	prev := int32(0)

	out := make([]part, 0, len(want))
	for i, wp := range want {
		if wp.PartNumber <= prev {
			return nil, s3err.InvalidPartOrder, fmt.Sprintf(
				"part %d (number %d) does not follow part number %d; parts must be listed in ascending order", i+1, wp.PartNumber, prev,
			)
		}

		prev = wp.PartNumber

		p, ok := s.parts[int(wp.PartNumber)]
		if !ok {
			return nil, s3err.InvalidPart, fmt.Sprintf("part %d was never uploaded to this upload", wp.PartNumber)
		}

		if want := strings.Trim(wp.ETag, `"`); want != "" && !strings.EqualFold(want, strings.Trim(p.etag, `"`)) {
			return nil, s3err.InvalidPart, fmt.Sprintf("part %d was uploaded with ETag %s, the completion list says %q",
				wp.PartNumber, p.etag, wp.ETag)
		}
		// Every part but the last must reach the S3 minimum. A shorter one means
		// the client's part size is wrong, and accepting it would write an object
		// no other S3 client could reproduce.
		if i < len(want)-1 && p.size < minPartSize {
			return nil, s3err.EntityTooSmall, fmt.Sprintf(
				"part %d is %d bytes; every part except the last must be at least %d bytes", wp.PartNumber, p.size, int64(minPartSize),
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
func assembleParts(dir string, parts []part) (string, int64, string, error) {
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
		src, err := os.Open(p.path)
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

		if n != p.size {
			return cleanup(fmt.Errorf("part %d is %d bytes on disk, %d bytes were uploaded and validated",
				i+1, n, p.size))
		}

		if got := hex.EncodeToString(md5Sum.Sum(nil)); !strings.EqualFold(got, strings.Trim(p.etag, `"`)) {
			return cleanup(fmt.Errorf("part %d hashes to %s on disk, it was uploaded as %s",
				i+1, got, strings.Trim(p.etag, `"`)))
		}

		total += n
	}

	if err := f.Sync(); err != nil {
		return cleanup(err)
	}

	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return "", 0, "", err
	}

	return path, total, hex.EncodeToString(h.Sum(nil)), nil
}

func (a *API) handleAbortMultipartUpload(w http.ResponseWriter, r *http.Request, bucket, clientKey string, prin port.Principal) {
	const op = "abort_multipart"

	s, ok := a.lookupSession(w, r, op, bucket, clientKey, prin, r.URL.Query().Get("uploadId"))
	if !ok {
		return
	}

	a.mp.drop(s)
	w.Header().Set("x-amz-request-id", s3err.RequestID(r))
	w.WriteHeader(http.StatusNoContent)
	a.metric(op, "ok")
}

// handleListParts answers the part inventory of a live upload. The AWS SDK in
// use here never calls it, but it is part of the multipart API and a client
// that resumes by asking is better served than by a 405.
func (a *API) handleListParts(w http.ResponseWriter, r *http.Request, bucket, clientKey string, prin port.Principal) {
	const op = "list_parts"

	s, ok := a.lookupSession(w, r, op, bucket, clientKey, prin, r.URL.Query().Get("uploadId"))
	if !ok {
		return
	}

	s.mu.Lock()
	nums := s.partNumbers()

	out := listPartsResult{
		XMLNS:        s3XMLNS,
		Bucket:       bucket,
		Key:          clientKey,
		UploadID:     s.uploadID,
		StorageClass: "STANDARD",
		MaxParts:     maxParts,
		Parts:        make([]partXML, 0, len(nums)),
	}
	for _, n := range nums {
		p := s.parts[n]
		out.Parts = append(out.Parts, partXML{PartNumber: wirePartNumber(n), ETag: p.etag, Size: p.size})
	}
	s.mu.Unlock()
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

// lookupSession resolves the uploadId query parameter to a session owned by
// prin. It writes the error response and returns false when it cannot: an
// unknown id and one owned by another principal are both NoSuchUpload on the
// wire, so the id cannot be probed for existence.
func (a *API) lookupSession(w http.ResponseWriter, r *http.Request, op, bucket, clientKey string,
	prin port.Principal, uploadID string,
) (*session, bool) {
	backendKey, err := a.backendKey(bucket, clientKey)
	if err != nil {
		a.metric(op, "error")
		s3err.WriteError(w, r, s3err.InvalidBucketName, "invalid object key")

		return nil, false
	}

	if uploadID == "" {
		a.metric(op, "error")
		s3err.WriteError(w, r, s3err.InvalidRequest, "uploadId is required")

		return nil, false
	}

	s, err := a.mp.get(uploadID, prin.AccessKeyID, backendKey)
	switch {
	case errors.Is(err, os.ErrNotExist):
		a.metric(op, "error")
		s3err.WriteError(w, r, s3err.NoSuchUpload, "")

		return nil, false
	case errors.Is(err, errForeignUpload):
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
	return a.mp.sweepExpired(a.mpTTL, a.mpMaxSessions)
}

// StartSweeper runs SweepExpired on an interval until ctx is cancelled; the
// first sweep runs immediately. A non-positive interval disables the loop.
//
// Without it an interrupted upload keeps its bytes on disk forever: nothing
// else in s3vault owns that directory. That makes this part of the work rather
// than an option.
func (a *API) StartSweeper(ctx context.Context, interval time.Duration) {
	if a.mp == nil || interval <= 0 {
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
