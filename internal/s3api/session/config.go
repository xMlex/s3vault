package session

import (
	"os"
	"path/filepath"
	"time"
)

// MultipartConfig parameterises the gateway's multipart spool.
type MultipartConfig struct {
	// Dir is the spool root; each session gets a subdirectory of it. It is
	// deliberately NOT cache.dir: the cache has its own invariants (TTL,
	// sweeper, lockfile) and is off by default, while multipart must work always.
	// Empty falls back to DefaultMultipartDir.
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
