package domain

import "time"

// FileInfo is a local file selected for archival.
type FileInfo struct {
	AbsPath string
	RelPath string
	Size    int64
	ModTime time.Time
}
