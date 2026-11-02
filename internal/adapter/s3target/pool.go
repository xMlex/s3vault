package s3target

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/xMlex/s3vault/internal/port"
)

// Defaults applied when a PoolConfig field is zero.
const (
	DefaultMax           = 64
	DefaultIdle          = 15 * time.Minute
	DefaultSweepInterval = time.Minute
)

// TargetResolver resolves a user's target to its ObjectStore. The facade calls
// it lazily, only for operations that actually touch storage.
type TargetResolver interface {
	Store(ctx context.Context, t port.S3Target) (port.ObjectStore, error)
}

// Builder constructs one ObjectStore for a target. It performs no network I/O.
type Builder func(ctx context.Context, t port.S3Target) (port.ObjectStore, error)

// PoolConfig configures a bounded per-process store pool.
type PoolConfig struct {
	Builder       Builder
	Max           int
	Idle          time.Duration
	SweepInterval time.Duration
	Logger        *slog.Logger
}

type poolEntry struct {
	store    port.ObjectStore
	lastUsed time.Time
}

// Pool reuses ObjectStores by target fingerprint. It is not an identity cache:
// Lookup still reads the database on every request; the pool only avoids
// rebuilding a store for a target that is already in use.
//
// Eviction never calls Close: port.ObjectStore has no lifecycle, and an evicted
// store may still be serving an in-flight request. Resources are released when
// the process exits.
type Pool struct {
	builder Builder
	max     int
	idle    time.Duration
	log     *slog.Logger

	mu      sync.Mutex
	entries map[string]*poolEntry

	sf singleflight.Group

	stop     chan struct{}
	done     chan struct{}
	stopOnce sync.Once
}

var _ TargetResolver = (*Pool)(nil)

// NewPool starts the idle sweeper. A zero SweepInterval disables it.
func NewPool(cfg PoolConfig) *Pool {
	if cfg.Max <= 0 {
		cfg.Max = DefaultMax
	}

	if cfg.Idle <= 0 {
		cfg.Idle = DefaultIdle
	}

	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	p := &Pool{
		builder: cfg.Builder,
		max:     cfg.Max,
		idle:    cfg.Idle,
		log:     cfg.Logger,
		entries: map[string]*poolEntry{},
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}

	go p.sweep(cfg.SweepInterval)

	return p
}

// Store returns the store for t, building it once per fingerprint.
func (p *Pool) Store(ctx context.Context, t port.S3Target) (port.ObjectStore, error) {
	key := Fingerprint(t)

	p.mu.Lock()
	if e, ok := p.entries[key]; ok {
		e.lastUsed = time.Now()
		p.mu.Unlock()

		return e.store, nil
	}
	p.mu.Unlock()

	v, err, _ := p.sf.Do(key, func() (any, error) {
		p.mu.Lock()
		if e, ok := p.entries[key]; ok {
			e.lastUsed = time.Now()
			p.mu.Unlock()

			return e.store, nil
		}
		p.mu.Unlock()

		store, buildErr := p.builder(ctx, t)
		if buildErr != nil {
			return nil, buildErr
		}

		p.mu.Lock()
		p.evictLocked()
		p.entries[key] = &poolEntry{store: store, lastUsed: time.Now()}
		p.mu.Unlock()

		return store, nil
	})
	if err != nil {
		return nil, fmt.Errorf("s3target: build store: %w", err)
	}

	store, ok := v.(port.ObjectStore)
	if !ok {
		return nil, errors.New("s3target: builder returned no store")
	}

	return store, nil
}

// evictLocked drops the least recently used entry when the pool is full. The
// new entry is not inserted yet, so the victim is always an existing one.
func (p *Pool) evictLocked() {
	if len(p.entries) < p.max {
		return
	}

	var (
		victimKey string
		victim    *poolEntry
	)

	for key, e := range p.entries {
		if victim == nil || e.lastUsed.Before(victim.lastUsed) {
			victimKey, victim = key, e
		}
	}

	if victim != nil {
		delete(p.entries, victimKey)
	}
}

// sweep drops entries idle for longer than the configured duration. It runs
// once a minute; a short interval exists only so tests do not wait.
func (p *Pool) sweep(interval time.Duration) {
	defer close(p.done)

	if interval <= 0 {
		return
	}

	t := time.NewTicker(interval)
	defer t.Stop()

	for {
		select {
		case <-p.stop:
			return
		case now := <-t.C:
			p.dropIdle(now)
		}
	}
}

func (p *Pool) dropIdle(now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for key, e := range p.entries {
		if now.Sub(e.lastUsed) >= p.idle {
			delete(p.entries, key)
		}
	}
}

// Close stops the sweeper. It does not close the stores it built.
func (p *Pool) Close() {
	p.stopOnce.Do(func() { close(p.stop) })
	<-p.done
}

// len reports the number of pooled stores. It is an inspection helper for the
// package's own tests.
func (p *Pool) len() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	return len(p.entries)
}
