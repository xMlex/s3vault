//go:build !unix

package cache

import "os"

func lockExclusive(_ *os.File) error { return nil }

// tryLockExclusive mirrors the unix build: without a real lock there is nothing
// to wait for, so the caller behaves as on an uncontended lock.
func tryLockExclusive(_ *os.File) (bool, error) { return true, nil }

func unlockExclusive(_ *os.File) error { return nil }
