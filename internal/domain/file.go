package domain

import "time"

// FileInfo is a local file selected for archival.
type FileInfo struct {
	AbsPath string
	RelPath string
	Size    int64
	ModTime time.Time
}

// FileVersion identifies one on-disk version of an object file. Size and
// ModTime alone are not enough: a sync tool that preserves timestamps can
// replace the bytes while keeping both, so ChangeTime, Inode and Device are
// part of the identity. ChangeTime is the inode change time, which userspace
// cannot backdate — every write or rename advances it. The last three fields
// are zero when the platform does not expose them, in which case identity
// falls back to Size and ModTime.
type FileVersion struct {
	Size       int64
	ModTime    time.Time
	ChangeTime time.Time
	Inode      uint64
	Device     uint64
}

// Equal reports whether two observations describe the same file version.
func (v FileVersion) Equal(other FileVersion) bool {
	return v.Size == other.Size &&
		v.ModTime.Equal(other.ModTime) &&
		v.ChangeTime.Equal(other.ChangeTime) &&
		v.Inode == other.Inode &&
		v.Device == other.Device
}
