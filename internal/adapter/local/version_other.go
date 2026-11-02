//go:build !linux && !darwin

package localstore

import (
	"io/fs"

	"github.com/xMlex/s3vault/internal/domain"
)

// applyFileChangeInfo is a no-op where the platform does not expose an inode
// change time: identity then rests on size and mtime only.
func applyFileChangeInfo(fs.FileInfo, *domain.FileVersion) {}
