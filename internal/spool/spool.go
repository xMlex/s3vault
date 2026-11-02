// Package spool names and reclaims the gateway's request-scoped plaintext
// files: a PutObject body while it is hashed, and a decrypted object served
// without a cache. They live outside cache.dir because they are swept by a
// different rule, and only the prefixes below are the spool's to delete.
package spool

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// PutPrefix marks a spooled PutObject body.
	PutPrefix = "s3vault-s3put-"
	// GetPrefix marks a decrypted object served without a cache.
	GetPrefix = "s3vault-serve-"
)

// Create makes a spool file in dir. An empty dir keeps os.CreateTemp's default
// location, which is what the CLI and tests use.
func Create(dir, prefix string) (*os.File, error) {
	return os.CreateTemp(dir, prefix+"*")
}

// Sweep removes spool files older than ttl and returns how many it removed.
// Anything without a spool prefix is left alone: the directory belongs to the
// operator and may hold unrelated files.
func Sweep(dir string, ttl time.Duration) int {
	if dir == "" || ttl <= 0 {
		return 0
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}

	cutoff := time.Now().Add(-ttl)
	removed := 0

	for _, e := range entries {
		if e.IsDir() || !hasSpoolPrefix(e.Name()) {
			continue
		}

		info, err := e.Info()
		if err != nil || info.ModTime().After(cutoff) {
			continue
		}

		if err := os.Remove(filepath.Join(dir, e.Name())); err == nil {
			removed++
		}
	}

	return removed
}

func hasSpoolPrefix(name string) bool {
	return strings.HasPrefix(name, PutPrefix) || strings.HasPrefix(name, GetPrefix)
}
