package session

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These are the white-box tests for the session registry. The black-box HTTP
// suite (internal/s3api/multipart_test.go, package s3api_test) proves the
// protocol; this one reaches the state the protocol hides, so the sweeper's
// rules can be checked against a clock the test controls instead of against real
// elapsed time. Living in the package also keeps the registry's surface small:
// count/dir are inspection helpers for these tests, not an API the facade needs.

func newTestRegistry(t *testing.T) *Registry {
	t.Helper()

	reg, err := New(MultipartConfig{Dir: t.TempDir()}, nil)
	require.NoError(t, err)

	return reg
}

func TestMPRegistryWipesStaleSpoolOnOpen(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(t.TempDir(), "spool")
	require.NoError(t, os.Mkdir(dir, 0o700))

	leftover := filepath.Join(dir, "mput-from-a-previous-process")
	require.NoError(t, os.MkdirAll(leftover, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(leftover, "part-00001"), []byte("orphaned"), 0o600))

	reg, err := New(MultipartConfig{Dir: dir}, nil)
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

// The spool root is created 0700 when it does not exist; an existing directory
// keeps its mode, exactly as backend.local.dir does. Session directories and part
// files stay 0700/0600 regardless.
func TestMPRegistryCreatesSpoolRoot0700(t *testing.T) {
	t.Parallel()

	dir := filepath.Join(t.TempDir(), "new-spool")
	_, err := New(MultipartConfig{Dir: dir}, nil)
	require.NoError(t, err)

	info, err := os.Stat(dir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), info.Mode().Perm())
}

// The spool root is a directory the operator points at, so the startup wipe must
// reach only session directories this facade creates. Removing the whole root
// erased whatever else lived there: a spool inside backend.local.dir took the
// objects with it, and nothing else in that directory had a say.
func TestMPRegistryLeavesUnrelatedEntriesAlone(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	stale := filepath.Join(dir, "mput-from-a-previous-process")
	require.NoError(t, os.MkdirAll(stale, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(stale, "part-00001"), []byte("orphaned"), 0o600))

	notOurs := filepath.Join(dir, "not-a-session")
	require.NoError(t, os.MkdirAll(notOurs, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(notOurs, "keep.txt"), []byte("keep"), 0o600))

	notes := filepath.Join(dir, "notes.txt")
	require.NoError(t, os.WriteFile(notes, []byte("operator data"), 0o600))

	_, err := New(MultipartConfig{Dir: dir}, nil)
	require.NoError(t, err)

	require.NoDirExists(t, stale, "a session directory from a dead process is still garbage")
	require.DirExists(t, notOurs, "a directory that is not a session must survive")
	require.FileExists(t, filepath.Join(notOurs, "keep.txt"))
	require.FileExists(t, notes)
}

func TestMPRegistryGetEnforcesOwnerAndKey(t *testing.T) {
	t.Parallel()

	reg := newTestRegistry(t)
	s, err := reg.Create("AKIAONE", "backups/a.bin")
	require.NoError(t, err)

	got, err := reg.Get(s.UploadID, "AKIAONE", "backups/a.bin")
	require.NoError(t, err)
	assert.Same(t, s, got)
	assert.True(t, reg.has(s.UploadID))

	// A different principal, the same id: the id is a capability bound to its
	// creator, so this must not resolve.
	_, err = reg.Get(s.UploadID, "AKIATWO", "backups/a.bin")
	require.ErrorIs(t, err, ErrForeignUpload)

	// The same principal, a different object: an upload id names one upload.
	_, err = reg.Get(s.UploadID, "AKIAONE", "backups/b.bin")
	require.ErrorIs(t, err, ErrForeignUpload)

	// The other way round, an unknown id is not "somebody else's".
	_, err = reg.Get("nope", "AKIAONE", "backups/a.bin")
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestMPRegistryDropRemovesFiles(t *testing.T) {
	t.Parallel()

	reg := newTestRegistry(t)
	s, err := reg.Create("AKIAONE", "backups/a.bin")
	require.NoError(t, err)

	partPath := s.PartPath(1)
	require.NoError(t, os.WriteFile(partPath, []byte("x"), 0o600))

	reg.Drop(s)
	assert.Equal(t, 0, reg.count())
	assert.False(t, reg.has(s.UploadID))

	_, err = os.Stat(s.Dir)
	require.ErrorIs(t, err, os.ErrNotExist)

	// Dropping twice is not an error: Complete and a racing Abort can both get
	// there, and the second one must not turn a success into a failure.
	reg.Drop(s)
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
				s, err := reg.Create("AKIA", "backups/a.bin")
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(s.PartPath(1), []byte("x"), 0o600))
				s.TouchedAt = now.Add(-idle)
				kept[s.Dir] = struct{}{}
			}

			swept := reg.sweepExpiredAt(ttl, tc.maxSessions, now)
			assert.Equal(t, len(tc.idle)-tc.wantKept, swept)
			assert.Equal(t, tc.wantKept, reg.count())

			// Every session that stayed is intact, and every one that went took
			// its files with it: this is the only thing that reclaims the disk.
			dirs, err := os.ReadDir(reg.spoolDir())
			require.NoError(t, err)
			require.Len(t, dirs, tc.wantKept)

			for _, d := range dirs {
				_, ok := kept[filepath.Join(reg.spoolDir(), d.Name())]
				assert.True(t, ok, "unexpected directory %s: a leftover would be a disk leak", d.Name())
			}
		})
	}
}

func TestMPRegistryUploadIDIsUnpredictable(t *testing.T) {
	t.Parallel()

	reg := newTestRegistry(t)
	seen := make(map[string]struct{}, 128)

	for range 128 {
		s, err := reg.Create("AKIA", "backups/a.bin")
		require.NoError(t, err)
		assert.Len(t, s.UploadID, 64, "256 bits of hex, like a real S3 upload id")
		_, dup := seen[s.UploadID]
		require.False(t, dup, "upload ids must not repeat")

		seen[s.UploadID] = struct{}{}
		reg.Drop(s)
	}
}
