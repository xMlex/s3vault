//go:build !unix

package cache

import "os"

func lockExclusive(_ *os.File) error { return nil }

func unlockExclusive(_ *os.File) error { return nil }
