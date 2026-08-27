package s3auth

import (
	"context"
	"strings"

	"github.com/xMlex/s3vault/internal/port"
)

// Static is a single-principal S3Identity from config.
type Static struct {
	AccessKey string
	SecretKey string
	Bucket    string // virtual bucket allowed for this principal
}

var _ port.S3Identity = (*Static)(nil)

// Lookup returns the configured principal when accessKeyID matches.
func (s *Static) Lookup(_ context.Context, accessKeyID string) (port.Principal, bool, error) {
	if s == nil || s.AccessKey == "" || accessKeyID != s.AccessKey {
		return port.Principal{}, false, nil
	}
	p := port.Principal{
		AccessKeyID: s.AccessKey,
		SecretKey:   s.SecretKey,
	}
	if s.Bucket != "" {
		p.AllowedBuckets = []string{s.Bucket}
	}
	return p, true, nil
}

// Allow permits ops on the configured virtual bucket (or any when Bucket empty for list-buckets).
func (s *Static) Allow(_ context.Context, p port.Principal, op port.S3Op, bucket, _ string) error {
	if op == port.S3OpListBuckets {
		return nil
	}
	want := s.Bucket
	if len(p.AllowedBuckets) > 0 {
		want = p.AllowedBuckets[0]
	}
	if want == "" {
		return nil
	}
	if !strings.EqualFold(bucket, want) {
		return port.ErrAccessDenied
	}
	return nil
}
