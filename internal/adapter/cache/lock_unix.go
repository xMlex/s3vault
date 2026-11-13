//go:build unix

package cache

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func lockExclusive(f *os.File) error {
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		return fmt.Errorf("flock: %w", err)
	}
	return nil
}

// tryLockExclusive takes LOCK_EX without blocking: ok=false means another
// holder has the lock right now.
func tryLockExclusive(f *os.File) (ok bool, err error) {
	err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, unix.EWOULDBLOCK):
		return false, nil
	default:
		return false, fmt.Errorf("flock: %w", err)
	}
}

func unlockExclusive(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_UN)
}
