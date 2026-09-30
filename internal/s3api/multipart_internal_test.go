package s3api

import (
	"crypto/md5" //nolint:gosec // test fixture mirroring S3's part ETag definition
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These are the white-box tests for the session registry. The black-box HTTP
// suite (multipart_test.go, package s3api_test) proves the protocol; this one
// reaches the state the protocol hides, so the sweeper's rules can be checked
// against a clock the test controls instead of against real elapsed time.

func newTestRegistry(t *testing.T) *mpRegistry {
	t.Helper()
	reg, err := newMPRegistry(MultipartConfig{Dir: t.TempDir()}, nil)
	require.NoError(t, err)

	return reg
}

func TestMPRegistryWipesStaleSpoolOnOpen(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	leftover := filepath.Join(dir, "mput-from-a-previous-process")
	require.NoError(t, os.MkdirAll(leftover, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(leftover, "part-00001"), []byte("orphaned"), 0o600))

	reg, err := newMPRegistry(MultipartConfig{Dir: dir}, nil)
	require.NoError(t, err)

	// A session belongs to the process that created it, so bytes left by another
	// one are garbage. Wiping here is what keeps a restart from accumulating
	// them forever.
	require.NoDirExists(t, leftover)
	assert.Equal(t, 0, reg.count())

	info, err := os.Stat(dir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), info.Mode().Perm(), "the spool root is 0700")
}

func TestMPRegistryGetEnforcesOwnerAndKey(t *testing.T) {
	t.Parallel()

	reg := newTestRegistry(t)
	s, err := reg.create("AKIAONE", "backups/a.bin")
	require.NoError(t, err)

	got, err := reg.get(s.uploadID, "AKIAONE", "backups/a.bin")
	require.NoError(t, err)
	assert.Same(t, s, got)

	// A different principal, the same id: the id is a capability bound to its
	// creator, so this must not resolve.
	_, err = reg.get(s.uploadID, "AKIATWO", "backups/a.bin")
	require.ErrorIs(t, err, errForeignUpload)

	// The same principal, a different object: an upload id names one upload.
	_, err = reg.get(s.uploadID, "AKIAONE", "backups/b.bin")
	require.ErrorIs(t, err, errForeignUpload)

	// The other way round, an unknown id is not "somebody else's".
	_, err = reg.get("nope", "AKIAONE", "backups/a.bin")
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestMPRegistryDropRemovesFiles(t *testing.T) {
	t.Parallel()

	reg := newTestRegistry(t)
	s, err := reg.create("AKIAONE", "backups/a.bin")
	require.NoError(t, err)

	partPath := s.partPath(1)
	require.NoError(t, os.WriteFile(partPath, []byte("x"), 0o600))

	reg.drop(s)
	assert.Equal(t, 0, reg.count())

	_, err = os.Stat(s.dir)
	require.ErrorIs(t, err, os.ErrNotExist)

	// Dropping twice is not an error: Complete and a racing Abort can both get
	// there, and the second one must not turn a success into a failure.
	reg.drop(s)
	assert.Equal(t, 0, reg.count())
}

func TestMPRegistrySweepExpiredAt(t *testing.T) {
	t.Parallel()

	const ttl = time.Hour

	now := time.Now()

	tests := []struct {
		name        string
		idle        []time.Duration // one per session, in creation order
		maxSessions int
		wantKept    int
	}{
		{name: "nothing is old enough", idle: []time.Duration{time.Minute, time.Minute}, maxSessions: 8, wantKept: 2},
		{name: "the old one goes", idle: []time.Duration{2 * ttl, time.Minute}, maxSessions: 8, wantKept: 1},
		{name: "all of them are old", idle: []time.Duration{2 * ttl, 3 * ttl}, maxSessions: 8, wantKept: 0},
		{
			// The limit protects spool space, so it evicts the least recently
			// touched rather than an arbitrary one.
			name: "over the session limit evicts the least recently used",
			idle: []time.Duration{time.Hour, 30 * time.Minute, time.Minute}, maxSessions: 2, wantKept: 2,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			reg := newTestRegistry(t)

			kept := make(map[string]struct{}, len(tc.idle))
			for _, idle := range tc.idle {
				s, err := reg.create("AKIA", "backups/a.bin")
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(s.partPath(1), []byte("x"), 0o600))
				s.touchedAt = now.Add(-idle)
				kept[s.dir] = struct{}{}
			}

			swept := reg.sweepExpiredAt(ttl, tc.maxSessions, now)
			assert.Equal(t, len(tc.idle)-tc.wantKept, swept)
			assert.Equal(t, tc.wantKept, reg.count())

			// Every session that stayed is intact, and every one that went took
			// its files with it: this is the only thing that reclaims the disk.
			dirs, err := os.ReadDir(reg.dir)
			require.NoError(t, err)
			require.Len(t, dirs, tc.wantKept)

			for _, d := range dirs {
				_, ok := kept[filepath.Join(reg.dir, d.Name())]
				assert.True(t, ok, "unexpected directory %s: a leftover would be a disk leak", d.Name())
			}
		})
	}
}

// The AWS SDK always serialises a well-formed CompleteMultipartUpload document,
// so the parse-failure branch is only reachable from a client that is not the
// SDK. It is separated out precisely so it can be tested without signing one.
// Assembly must check the bytes it actually reads, not only the sizes and ETags
// resolveParts validated.
//
// resolveParts reads s.parts under the session lock and validates sizes and
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

			_, size, sum, err := assembleParts(dir, []part{{path: path, size: tc.recSize, etag: `"` + etag + `"`}})
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

	_, _, _, err := assembleParts(dir, []part{{path: path, size: 999, etag: `"` + md5hex("0123456789") + `"`}})
	require.Error(t, err)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Len(t, entries, 1, "only the part itself should remain, no assembled- file")
}

// A part upload that is still streaming pins its session. touchedAt is bumped on
// recordPart, which runs after the body has been consumed — so from the moment a
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
	api := &API{mp: reg, mpTTL: ttl}

	s, err := reg.create("AKIA", "k")
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

	removed := reg.sweepExpiredAt(ttl, 64, time.Now())
	assert.Zero(t, removed, "an upload in progress is not an idle session")
	assert.NotNil(t, reg.sessions[s.uploadID], "the session must survive its own in-flight part")

	close(release)
	require.NoError(t, <-done)

	// The pin is not a way to keep a dead session alive: once the write lands and
	// the client stops, the same sweep reclaims it.
	time.Sleep(2 * ttl)
	assert.Positive(t, reg.sweepExpiredAt(ttl, 64, time.Now()))
	assert.Nil(t, reg.sessions[s.uploadID], "an idle session must still be reclaimable")
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

func TestMPRegistryUploadIDIsUnpredictable(t *testing.T) {
	t.Parallel()

	reg := newTestRegistry(t)
	seen := make(map[string]struct{}, 128)

	for range 128 {
		s, err := reg.create("AKIA", "backups/a.bin")
		require.NoError(t, err)
		assert.Len(t, s.uploadID, 64, "256 bits of hex, like a real S3 upload id")
		_, dup := seen[s.uploadID]
		require.False(t, dup, "upload ids must not repeat")

		seen[s.uploadID] = struct{}{}
		reg.drop(s)
	}
}

func md5hex(s string) string {
	sum := md5.Sum([]byte(s)) //nolint:gosec // test fixture mirroring S3's part ETag definition

	return hex.EncodeToString(sum[:])
}

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))

	return hex.EncodeToString(sum[:])
}
