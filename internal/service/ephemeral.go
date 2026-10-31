package service

import (
	"context"
	"os"
	"sync"
	"time"
)

// ephemeralFile is one in-flight or finished plaintext temp file. ready is
// closed when load finishes; refs counts every caller interested in the result,
// so the file is removed once and only once, by the last one.
type ephemeralFile struct {
	ready chan struct{}
	done  bool
	refs  int
	err   error

	path    string
	size    int64
	name    string
	modTime time.Time
	etag    string
	sha256  string
}

// ephemeralSet collapses concurrent cold reads of one key onto a single
// download. Without a cache every reader used to fetch the object for itself:
// sixteen parallel GETs of one 10 GiB key meant sixteen downloads and sixteen
// copies on disk.
type ephemeralSet struct {
	mu    sync.Mutex
	files map[string]*ephemeralFile
}

func newEphemeralSet() *ephemeralSet {
	return &ephemeralSet{files: make(map[string]*ephemeralFile)}
}

// acquire returns the shared plaintext file for key, starting load when this is
// the first caller. Waiters block until the load finishes; a failed load is
// reported to all of them instead of each starting a download of its own.
func (s *ephemeralSet) acquire(ctx context.Context, key string, load func(*ephemeralFile) error) (CachedPlaintext, error) {
	s.mu.Lock()
	if e, ok := s.files[key]; ok {
		s.mu.Unlock()

		return s.join(ctx, key, e)
	}

	e := &ephemeralFile{ready: make(chan struct{}), refs: 1}
	s.files[key] = e
	s.mu.Unlock()

	err := load(e)

	s.mu.Lock()
	e.done = true

	e.err = err
	if err != nil {
		s.dropLocked(key, e)
	}
	s.mu.Unlock()
	close(e.ready)

	if err != nil {
		return CachedPlaintext{}, err
	}

	return e.cached(s, key), nil
}

// join waits for an existing entry's load and takes a reference on its result.
func (s *ephemeralSet) join(ctx context.Context, key string, e *ephemeralFile) (CachedPlaintext, error) {
	s.mu.Lock()

	held := false

	if !e.done {
		// Count this caller before waiting, so the entry cannot be removed from
		// under it while the load runs.
		e.refs++
		held = true
		ready := e.ready
		s.mu.Unlock()

		select {
		case <-ready:
		case <-ctx.Done():
			s.mu.Lock()
			s.dropLocked(key, e)
			s.mu.Unlock()

			return CachedPlaintext{}, ctx.Err()
		}

		s.mu.Lock()
	}

	if e.err != nil {
		// Only a caller that took a reference above may drop one; a caller that
		// merely observed the finished error leaves the entry to the loader.
		if held {
			s.dropLocked(key, e)
		}
		s.mu.Unlock()

		return CachedPlaintext{}, e.err
	}

	if !held {
		e.refs++
	}
	s.mu.Unlock()

	return e.cached(s, key), nil
}

// release drops one caller's reference and removes the file with the last one.
func (s *ephemeralSet) release(key string, e *ephemeralFile) {
	s.mu.Lock()
	s.dropLocked(key, e)
	s.mu.Unlock()
}

// dropLocked must be called with s.mu held.
func (s *ephemeralSet) dropLocked(key string, e *ephemeralFile) {
	e.refs--
	if e.refs > 0 {
		return
	}
	// Only this entry may be deleted: a later reader may already have started a
	// fresh load under the same key.
	if cur, ok := s.files[key]; ok && cur == e {
		delete(s.files, key)
	}

	if e.path != "" {
		_ = os.Remove(e.path)
		e.path = ""
	}
}

func (e *ephemeralFile) cached(s *ephemeralSet, key string) CachedPlaintext {
	c := CachedPlaintext{
		Path:      e.path,
		Size:      e.size,
		Name:      e.name,
		ModTime:   e.modTime,
		ETag:      e.etag,
		SHA256:    e.sha256,
		Ephemeral: true,
	}

	var once sync.Once

	c.release = func() {
		once.Do(func() { s.release(key, e) })
	}

	return c
}
