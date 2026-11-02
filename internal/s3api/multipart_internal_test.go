package s3api

import (
	"crypto/md5" //nolint:gosec // test fixture mirroring S3's part ETag definition
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/stretchr/testify/require"
	sessions "github.com/xMlex/s3vault/internal/s3api/session"
)

// newTestRegistry builds a registry in a temp spool for the tests below that
// drive a session through the facade. The registry's own white-box tests live in
// internal/s3api/session/registry_test.go, next to the package they inspect.
func newTestRegistry(t *testing.T) *sessions.Registry {
	t.Helper()
	reg, err := sessions.New(MultipartConfig{Dir: t.TempDir()}, nil)
	require.NoError(t, err)

	return reg
}

// The AWS SDK always serialises a well-formed CompleteMultipartUpload document,
// so the parse-failure branch is only reachable from a client that is not the
// SDK. It is separated out precisely so it can be tested without signing one.
// Assembly must check the bytes it actually reads, not only the sizes and ETags
// resolveParts validated.
//
// resolveParts reads s.Parts under the session lock and validates sizes and
// ETags there; assembleParts then opens those same paths *outside* that lock. A
// concurrent UploadPart for the same number re-opens the path with O_TRUNC and
// rewrites it, so the validated record and the bytes on disk can disagree — and
// before this check the gateway happily assembled the replacement, answered 200
// with the SHA-256 of content the client never listed, and could write an object
// whose non-final part is under the S3 minimum. Same length, different content is
// the same story, which is why the ETag is verified too and not just the size.
func TestAssemblePartsRejectsBytesThatNoLongerMatchThePart(t *testing.T) {
	t.Parallel()

	const body = "0123456789"

	cases := []struct {
		name    string
		onDisk  string
		recSize int64
		recETag string // unquoted MD5 hex; "" means "the ETag of onDisk as uploaded"
	}{
		{
			name:    "intact",
			onDisk:  body,
			recSize: int64(len(body)),
		},
		{
			name:    "truncated under the recorded size",
			onDisk:  body[:4],
			recSize: int64(len(body)),
		},
		{
			name:    "grown past the recorded size",
			onDisk:  body + body,
			recSize: int64(len(body)),
		},
		{
			name:    "same length, different content",
			onDisk:  "abcdefghij",
			recSize: int64(len(body)),
			recETag: md5hex(body),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			path := filepath.Join(dir, "part-00001")
			require.NoError(t, os.WriteFile(path, []byte(tc.onDisk), 0o600))

			etag := tc.recETag
			if etag == "" {
				etag = md5hex(tc.onDisk)
			}

			_, size, sum, err := assembleParts(dir, []sessions.Part{{Path: path, Size: tc.recSize, ETag: `"` + etag + `"`}})
			if tc.name == "intact" {
				require.NoError(t, err)
				assert.Equal(t, int64(len(tc.onDisk)), size)
				assert.Equal(t, sha256hex(tc.onDisk), sum)

				return
			}

			require.Error(t, err, "assembly must not publish bytes it never validated")
			assert.Empty(t, sum)
			assert.Zero(t, size)
		})
	}
}

// The assembled file is removed on the failure path too, so a rejected assembly
// leaves no plaintext behind.
func TestAssemblePartsRemovesOutputOnRejection(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "part-00001")
	require.NoError(t, os.WriteFile(path, []byte("0123456789"), 0o600))

	_, _, _, err := assembleParts(dir, []sessions.Part{{Path: path, Size: 999, ETag: `"` + md5hex("0123456789") + `"`}})
	require.Error(t, err)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Len(t, entries, 1, "only the part itself should remain, no assembled- file")
}

// A retry of a part that fails half-way must leave the part it was replacing
// intact. S3 replaces a number atomically: the previously accepted bytes survive
// a re-upload that never completes. spoolPart used to open partPath with
// O_TRUNC, so the old part was destroyed before the replacement's first byte
// arrived, and the error path then removed the file altogether while s.Parts
// still pointed at it — ListParts advertised a part that Complete could only
// fail on.
func TestFailedUploadPartKeepsPreviouslyAcceptedPart(t *testing.T) {
	t.Parallel()

	reg := newTestRegistry(t)
	api := &API{mpSess: reg}

	s, err := reg.Create("AKIA", "k")
	require.NoError(t, err)

	const good = "0123456789"

	etag, err := api.spoolPart(s, 1, strings.NewReader(good))
	require.NoError(t, err)

	// The retry dies after its first chunk, as a dropped connection does.
	_, err = api.spoolPart(s, 1, io.MultiReader(
		strings.NewReader("bad"),
		readerFunc(func([]byte) (int, error) { return 0, errConnectionReset }),
	))
	require.Error(t, err)

	// The accepted part is still on disk, byte for byte, and still the record
	// Complete will get.
	p, ok := s.Parts[1]
	require.True(t, ok, "an accepted part must stay in the session")
	assert.Equal(t, etag, p.ETag)
	assert.Equal(t, int64(len(good)), p.Size)

	body, err := os.ReadFile(s.PartPath(1))
	require.NoError(t, err)
	assert.Equal(t, good, string(body))

	// Nothing half-written is left beside it.
	entries, err := os.ReadDir(s.Dir)
	require.NoError(t, err)
	require.Len(t, entries, 1, "a failed retry must leave no temp file, the old part only")
	assert.Equal(t, "part-00001", entries[0].Name())

	_, size, sum, err := assembleParts(s.Dir, []sessions.Part{p})
	require.NoError(t, err, "Complete must still be able to assemble the accepted part")
	assert.Equal(t, int64(len(good)), size)
	assert.Equal(t, sha256hex(good), sum)
}

// The same guarantee holds when the retry is rejected by the spool budget
// rather than by the body: the limits are checked before the replacement is
// published, so a refused part cannot have already overwritten the old one.
func TestPartRejectedByBudgetKeepsPreviouslyAcceptedPart(t *testing.T) {
	t.Parallel()

	reg := newTestRegistry(t)
	api := &API{mpSess: reg, mpMaxBytes: 10}

	s, err := reg.Create("AKIA", "k")
	require.NoError(t, err)

	const good = "0123456789"

	etag, err := api.spoolPart(s, 1, strings.NewReader(good))
	require.NoError(t, err)

	_, err = api.spoolPart(s, 1, strings.NewReader(good+"more"))
	require.Error(t, err, "the session budget must reject the larger replacement")

	p, ok := s.Parts[1]
	require.True(t, ok)
	assert.Equal(t, etag, p.ETag)
	assert.Equal(t, int64(len(good)), p.Size)

	body, err := os.ReadFile(s.PartPath(1))
	require.NoError(t, err)
	assert.Equal(t, good, string(body))

	assert.Equal(t, int64(len(good)), s.Bytes, "a rejected part must not change the session's byte total")
}

var errConnectionReset = errors.New("connection reset by peer")

// A part upload that is still streaming pins its session. touchedAt is bumped on
// publishPart, which runs after the body has been consumed — so from the moment a
// part starts arriving until it lands, the session still carries the stamp of
// whatever happened before. A client that opens a session, waits out the TTL and
// then streams a slow part is swept mid-write: the sweeper drops it and RemoveAlls
// the directory under the open file, and the client is told 200 with an ETag for
// bytes that have just been deleted. Its Complete then answers NoSuchUpload.
//
// Real durations rather than an injected clock, because touchedAt is time.Now():
// the test needs the *idle gap before* the write to exceed the TTL while the
// write itself does not, and a clock that could be moved would hide exactly that.
func TestInFlightUploadPartPinsTheSession(t *testing.T) {
	t.Parallel()

	const ttl = 300 * time.Millisecond

	reg := newTestRegistry(t)
	api := &API{mpSess: reg, mpTTL: ttl}

	s, err := reg.Create("AKIA", "k")
	require.NoError(t, err)

	// The client opens a session and then sits on it for longer than the TTL.
	// Nothing sweeps in between — lazy expiry only happens when the sweeper runs,
	// which is the point: the sweep below is the first thing to look.
	time.Sleep(2 * ttl)

	entered := make(chan struct{})
	release := make(chan struct{})

	body := io.MultiReader(
		strings.NewReader("head"),
		readerFunc(func([]byte) (int, error) {
			close(entered)
			<-release

			return 0, io.EOF
		}),
	)

	done := make(chan error, 1)

	go func() {
		_, err := api.spoolPart(s, 1, body)

		done <- err
	}()

	<-entered

	removed := reg.SweepExpired(ttl, 64)
	assert.Zero(t, removed, "an upload in progress is not an idle session")

	live, err := reg.Get(s.UploadID, "AKIA", "k")
	require.NoError(t, err, "the session must survive its own in-flight part")
	assert.Same(t, s, live)

	close(release)
	require.NoError(t, <-done)

	// The pin is not a way to keep a dead session alive: once the write lands and
	// the client stops, the same sweep reclaims it.
	time.Sleep(2 * ttl)
	assert.Positive(t, reg.SweepExpired(ttl, 64))

	_, err = reg.Get(s.UploadID, "AKIA", "k")
	require.ErrorIs(t, err, os.ErrNotExist, "an idle session must still be reclaimable")
}

// readerFunc adapts a func to io.Reader.
type readerFunc func(p []byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

func TestParseCompleteBody(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		body    string
		want    []partXML
		wantErr bool
	}{
		{name: "empty body is not a parse failure", body: ""},
		{name: "whitespace-only body is not a parse failure", body: " \n\t "},
		{
			// This is what aws-cli sends when --multipart-upload is omitted, and
			// S3 reads it as "assemble from every part you uploaded".
			name: "document with no parts", body: `<CompleteMultipartUpload></CompleteMultipartUpload>`,
		},
		{
			name: "one part",
			body: `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"abc"</ETag><Size>7</Size></Part></CompleteMultipartUpload>`,
			want: []partXML{{PartNumber: 1, ETag: `"abc"`, Size: 7}},
		},
		{
			name: "parts in document order",
			body: `<CompleteMultipartUpload>` +
				`<Part><PartNumber>3</PartNumber></Part><Part><PartNumber>1</PartNumber></Part>` +
				`</CompleteMultipartUpload>`,
			// Order is preserved verbatim: resolveParts is where ascending order
			// is enforced, and reordering here would hide InvalidPartOrder.
			want: []partXML{{PartNumber: 3}, {PartNumber: 1}},
		},
		{name: "truncated document", body: `<CompleteMultipartUpload><Part>`, wantErr: true},
		{name: "not xml at all", body: `this is not xml`, wantErr: true},
		{name: "wrong root element", body: `<Nope/>`, wantErr: true},
		{
			// The decoder ends in io.EOF on plain text too, so the empty-body case
			// must be told apart by peeking rather than by the error value.
			name: "character data only", body: `42`, wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseCompleteBody(strings.NewReader(tc.body))
			if tc.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// The body is bounded, so a client cannot stream an unbounded document into the
// decoder; the cap has to actually cap.
func TestParseCompleteBodyIsBounded(t *testing.T) {
	t.Parallel()

	huge := "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>" +
		strings.Repeat("a", maxCompleteBody+1) + "</ETag></Part></CompleteMultipartUpload>"
	_, err := parseCompleteBody(strings.NewReader(huge))
	require.Error(t, err, "a document past the cap must fail rather than be read whole")
}

func md5hex(s string) string {
	sum := md5.Sum([]byte(s)) //nolint:gosec // test fixture mirroring S3's part ETag definition

	return hex.EncodeToString(sum[:])
}

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))

	return hex.EncodeToString(sum[:])
}
