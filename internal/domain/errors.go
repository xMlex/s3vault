package domain

import "errors"

var (
	ErrNotFound        = errors.New("object not found")
	ErrInvalidPath     = errors.New("invalid path")
	ErrSymlinkEscape   = errors.New("symlink target is outside scan root")
	ErrNotRegularFile  = errors.New("not a regular file")
	ErrSymlinkSkipped  = errors.New("symlink not followed")
	ErrStoreRequired   = errors.New("object store is required unless --dry-run")
	ErrPartialFailures = errors.New("one or more files failed")
)
