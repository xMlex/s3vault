package domain

import "time"

// ArchiveStats is the summary of an archive/upload run.
type ArchiveStats struct {
	Found         int           `json:"found"`
	Uploaded      int           `json:"uploaded"`
	Skipped       int           `json:"skipped"`
	Failed        int           `json:"failed"`
	BytesUploaded int64         `json:"bytes_uploaded"`
	Duration      time.Duration `json:"duration"`
}
