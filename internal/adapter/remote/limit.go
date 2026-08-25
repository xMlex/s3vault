package remote

import (
	"context"
	"io"
	"sync"
	"time"
)

// Limiter caps aggregate bytes/sec across concurrent Readers. Zero or negative disables limiting.
type Limiter struct {
	bps int64

	mu      sync.Mutex
	tokens  float64
	last    time.Time
	started bool
}

// NewLimiter returns a shared bandwidth limiter.
func NewLimiter(bytesPerSec int64) *Limiter {
	return &Limiter{bps: bytesPerSec}
}

// Reader wraps r so Read calls consume from the shared budget.
func (l *Limiter) Reader(ctx context.Context, r io.Reader) io.Reader {
	if l == nil || l.bps <= 0 {
		return r
	}
	return &limitedReader{ctx: ctx, r: r, lim: l}
}

type limitedReader struct {
	ctx context.Context
	r   io.Reader
	lim *Limiter
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if err := l.ctx.Err(); err != nil {
		return 0, err
	}
	maxChunk := int(l.lim.bps)
	if maxChunk > len(p) {
		maxChunk = len(p)
	}
	if maxChunk > 64*1024 {
		maxChunk = 64 * 1024
	}
	if maxChunk < 1 {
		maxChunk = 1
	}
	if err := l.lim.wait(l.ctx, maxChunk); err != nil {
		return 0, err
	}
	n, err := l.r.Read(p[:maxChunk])
	if n > 0 {
		l.lim.refund(maxChunk - n)
	} else {
		l.lim.refund(maxChunk)
	}
	return n, err
}

func (l *Limiter) wait(ctx context.Context, n int) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if !l.started {
		l.tokens = float64(l.bps)
		l.last = now
		l.started = true
	} else {
		elapsed := now.Sub(l.last).Seconds()
		l.tokens += elapsed * float64(l.bps)
		if l.tokens > float64(l.bps) {
			l.tokens = float64(l.bps)
		}
		l.last = now
	}
	need := float64(n)
	for l.tokens < need {
		if err := ctx.Err(); err != nil {
			return err
		}
		deficit := need - l.tokens
		sleep := time.Duration(deficit / float64(l.bps) * float64(time.Second))
		if sleep < time.Millisecond {
			sleep = time.Millisecond
		}
		l.mu.Unlock()
		timer := time.NewTimer(sleep)
		select {
		case <-ctx.Done():
			timer.Stop()
			l.mu.Lock()
			return ctx.Err()
		case <-timer.C:
		}
		l.mu.Lock()
		now = time.Now()
		elapsed := now.Sub(l.last).Seconds()
		l.tokens += elapsed * float64(l.bps)
		if l.tokens > float64(l.bps) {
			l.tokens = float64(l.bps)
		}
		l.last = now
	}
	l.tokens -= need
	return nil
}

func (l *Limiter) refund(n int) {
	if n <= 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.tokens += float64(n)
	if l.tokens > float64(l.bps) {
		l.tokens = float64(l.bps)
	}
}
