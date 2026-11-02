package localstore

import (
	"io/fs"

	"github.com/xMlex/s3vault/internal/domain"
)

// FileVersionOf captures the identity a cache entry must match to be considered
// fresh. Size and mtime alone cannot tell a rewritten file from an unchanged
// one when a sync tool preserves timestamps, so the platform-specific part adds
// the inode change time and the file identity.
func FileVersionOf(fi fs.FileInfo) domain.FileVersion {
	v := domain.FileVersion{Size: fi.Size(), ModTime: fi.ModTime()}
	applyFileChangeInfo(fi, &v)

	return v
}
