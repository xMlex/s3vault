package domain

import "time"

// ListOptions selects a page of object keys (S3 ListObjectsV2 semantics).
type ListOptions struct {
	Prefix            string
	Delimiter         string
	MaxKeys           int32
	ContinuationToken string
	StartAfter        string
}

// ListObject is one key in a ListPage.
type ListObject struct {
	Key          string
	Size         int64
	ETag         string
	LastModified time.Time
}

// ListPage is one page of List results.
type ListPage struct {
	Contents              []ListObject
	CommonPrefixes        []string
	IsTruncated           bool
	NextContinuationToken string
	KeyCount              int32
}
