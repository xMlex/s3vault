// Package session holds the gateway's in-flight multipart uploads: the spool
// files, the session registry and the sweeper that reclaims them.
package session

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// ErrForeignUpload is returned when a principal addresses a session it did not
// create. On the wire it is indistinguishable from "no such upload" — both
// answer NoSuchUpload — so the id cannot be probed for existence; the log line
// is where the real reason survives.
var ErrForeignUpload = errors.New("upload id belongs to another principal")

// Part is one uploaded part: a file in the session directory plus what
// CompleteMultipartUpload needs to verify and assemble it.
type Part struct {
	Path string // file in the session's spool directory
	Size int64
	ETag string // MD5 hex, quoted — the value returned to the client
}

// Session is one in-flight multipart upload.
//
// Mu guards Parts, Bytes and TouchedAt. A lock per session, rather than one for
// the whole registry, keeps a Complete — which holds the session for the length
// of the whole assembly — from blocking the UploadPart of an unrelated upload.
type Session struct {
	Mu                 sync.Mutex
	UploadID           string
	BackendKey         string
	AccessKeyID        string
	UserID             int64
	ClientKey          string
	Prefix             string
	ProfileFingerprint string
	TargetFingerprint  string
	CreatedAt          time.Time
	TouchedAt          time.Time
	Parts              map[int]Part
	Dir                string
	Bytes              int64
}

// PartPath is the on-disk name of a part. The number is the file name, so
// re-uploading a part replaces it — as in S3.
func (s *Session) PartPath(number int) string {
	return filepath.Join(s.Dir, fmt.Sprintf("part-%05d", number))
}

// PartNumbers returns the uploaded part numbers in ascending order.
func (s *Session) PartNumbers() []int {
	nums := make([]int, 0, len(s.Parts))
	for n := range s.Parts {
		nums = append(nums, n)
	}

	slices.Sort(nums)

	return nums
}

// Touch stamps the session as active. It is called at the start of a part write
// as well as after it lands, so the sweeper's notion of idle cannot fall inside
// a write in progress.
func (s *Session) Touch() {
	s.Mu.Lock()
	defer s.Mu.Unlock()

	s.TouchedAt = time.Now()
}

// Registry holds the live multipart sessions of one process.
//
// Sessions do not survive a restart: the registry is in memory and the spool
// root is wiped when it is opened, so an interrupted upload leaves nothing for
// the next process to half-adopt.
type Registry struct {
	mu       sync.Mutex
	dir      string
	sessions map[string]*Session
	log      *slog.Logger
}

// New prepares the spool root and returns an empty registry.
//
// A session belongs to the process that created it, so a session directory
// already in the spool root belongs to a process that is gone and is removed.
// Only those are removed: the root is an operator-chosen directory, and wiping
// all of it would delete whatever else lives there.
func New(cfg MultipartConfig, log *slog.Logger) (*Registry, error) {
	dir, err := filepath.Abs(cfg.Dir)
	if err != nil {
		return nil, fmt.Errorf("multipart spool dir: %w", err)
	}

	if err := removeStaleSessions(dir); err != nil {
		return nil, fmt.Errorf("multipart spool dir %s: %w", dir, err)
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("multipart spool dir %s: %w", dir, err)
	}

	if log == nil {
		log = slog.Default()
	}

	return &Registry{dir: dir, sessions: map[string]*Session{}, log: log}, nil
}

// sessionDirPrefix names a session directory in the spool root. os.MkdirTemp
// appends a random suffix, so the prefix is all a stale directory can be
// recognised by.
const sessionDirPrefix = "mput-"

// removeStaleSessions deletes session directories left by a dead process and
// nothing else.
func removeStaleSessions(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil // MkdirAll in the caller creates it
		}

		return err
	}

	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), sessionDirPrefix) {
			continue
		}

		if err := os.RemoveAll(filepath.Join(dir, e.Name())); err != nil {
			return err
		}
	}

	return nil
}

// Create registers a static/legacy session: access key plus backend key only.
// It is kept for tests and for callers that have no per-user policy.
func (reg *Registry) Create(accessKeyID, backendKey string) (*Session, error) {
	return reg.CreateForUser(accessKeyID, 0, "", "", "", "", backendKey)
}

// CreateForUser registers a session bound to the user's namespace, profile and
// destination snapshot. The snapshot is what UploadPart and Complete compare
// against later.
func (reg *Registry) CreateForUser(accessKeyID string, userID int64, clientKey, prefix, profileFP, targetFP, backendKey string) (*Session, error) {
	uploadID, err := newUploadID()
	if err != nil {
		return nil, err
	}

	dir, err := os.MkdirTemp(reg.dir, sessionDirPrefix)
	if err != nil {
		return nil, fmt.Errorf("multipart session dir: %w", err)
	}

	now := time.Now()
	s := &Session{
		UploadID:           uploadID,
		BackendKey:         backendKey,
		AccessKeyID:        accessKeyID,
		UserID:             userID,
		ClientKey:          clientKey,
		Prefix:             prefix,
		ProfileFingerprint: profileFP,
		TargetFingerprint:  targetFP,
		CreatedAt:          now,
		TouchedAt:          now,
		Parts:              map[int]Part{},
		Dir:                dir,
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

// Get looks a session up and enforces that the caller owns it.
//
// Binding to AccessKeyID *and* to BackendKey is the reason a session is not just
// a random id: otherwise any authenticated client could append parts to somebody
// else's object.
func (reg *Registry) Get(uploadID, accessKeyID, backendKey string) (*Session, error) {
	s, err := reg.lookup(uploadID)
	if err != nil {
		return nil, err
	}

	if s.AccessKeyID != accessKeyID || s.BackendKey != backendKey {
		return nil, ErrForeignUpload
	}

	return s, nil
}

// GetForWrite checks ownership, the object key the upload was created for, and
// the policy snapshot: user id, transparent prefix, profile fingerprint and
// destination fingerprint.
func (reg *Registry) GetForWrite(uploadID, accessKeyID, clientKey, backendKey string,
	userID int64, prefix, profileFP, targetFP string,
) (*Session, error) {
	s, err := reg.lookup(uploadID)
	if err != nil {
		return nil, err
	}

	if s.AccessKeyID != accessKeyID ||
		s.ClientKey != clientKey ||
		s.BackendKey != backendKey ||
		s.UserID != userID ||
		s.Prefix != prefix ||
		s.ProfileFingerprint != profileFP ||
		s.TargetFingerprint != targetFP {
		return nil, ErrForeignUpload
	}

	return s, nil
}

// GetForOwner checks only the access key and client key. Abort/ListParts must
// keep working after a prefix or profile change, and they never read or write
// object bytes.
func (reg *Registry) GetForOwner(uploadID, accessKeyID, clientKey string) (*Session, error) {
	s, err := reg.lookup(uploadID)
	if err != nil {
		return nil, err
	}

	if s.AccessKeyID != accessKeyID || s.ClientKey != clientKey {
		return nil, ErrForeignUpload
	}

	return s, nil
}

func (reg *Registry) lookup(uploadID string) (*Session, error) {
	reg.mu.Lock()
	s, ok := reg.sessions[uploadID]
	reg.mu.Unlock()

	if !ok {
		return nil, os.ErrNotExist
	}

	return s, nil
}

// Drop unregisters a session and removes its files. Safe to call twice.
func (reg *Registry) Drop(s *Session) {
	if s == nil {
		return
	}

	reg.mu.Lock()
	delete(reg.sessions, s.UploadID)
	reg.mu.Unlock()

	reg.remove(s)
}

func (reg *Registry) remove(s *Session) {
	if s == nil {
		return
	}

	if err := os.RemoveAll(s.Dir); err != nil {
		reg.log.Warn("s3 multipart session cleanup",
			slog.String("op", "s3.multipart"),
			slog.String("err", err.Error()),
		)
	}
}

// SweepExpired drops sessions untouched for longer than ttl, plus any over
// maxSessions, and returns how many it removed. It is the only thing that
// reclaims the spool after an interrupted upload: no other timer in s3vault
// would notice.
func (reg *Registry) SweepExpired(ttl time.Duration, maxSessions int) int {
	return reg.sweepExpiredAt(ttl, maxSessions, time.Now())
}

// sweepExpiredAt is SweepExpired with an explicit clock, so the sweeper's rules
// can be tested without waiting real time.
func (reg *Registry) sweepExpiredAt(ttl time.Duration, maxSessions int, now time.Time) int {
	// Collect under the registry lock, delete files outside it: RemoveAll can
	// block on I/O and the registry lock is on the path of every UploadPart.
	reg.mu.Lock()

	// Snapshot (session, touchedAt) pairs under both locks: sorting by activity
	// while a concurrent UploadPart is bumping TouchedAt would otherwise race.
	type aged struct {
		s       *Session
		touched time.Time
	}

	live := make([]aged, 0, len(reg.sessions))

	var expired []*Session

	for id, s := range reg.sessions {
		s.Mu.Lock()
		touched := s.TouchedAt
		s.Mu.Unlock()

		if ttl > 0 && now.Sub(touched) >= ttl {
			delete(reg.sessions, id)

			expired = append(expired, s)

			continue
		}

		live = append(live, aged{s: s, touched: touched})
	}

	// Over the limit: the least recently touched goes first, because spool
	// space is the resource being protected, not the session count.
	if maxSessions > 0 {
		if over := len(live) - maxSessions; over > 0 {
			slices.SortFunc(live, func(x, y aged) int { return x.touched.Compare(y.touched) })

			for i := 0; i < over && i < len(live); i++ {
				delete(reg.sessions, live[i].s.UploadID)

				expired = append(expired, live[i].s)
			}
		}
	}

	reg.mu.Unlock()

	for _, s := range expired {
		reg.remove(s)
	}

	return len(expired)
}

// count reports the number of live sessions. It is an inspection helper for the
// package's own tests, not part of the surface the facade uses.
func (reg *Registry) count() int {
	reg.mu.Lock()
	defer reg.mu.Unlock()

	return len(reg.sessions)
}

// spoolDir is the spool root the registry was opened with. It is an inspection
// helper for the package's own tests.
func (reg *Registry) spoolDir() string {
	return reg.dir
}

// has reports whether uploadID is a live session.
func (reg *Registry) has(uploadID string) bool {
	reg.mu.Lock()
	defer reg.mu.Unlock()

	_, ok := reg.sessions[uploadID]

	return ok
}
