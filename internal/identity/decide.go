package identity

import "github.com/xMlex/s3vault/internal/domain"

// Action is the upload pipeline decision for one file.
type Action int

const (
	ActionUnknown Action = iota
	ActionUpload
	ActionSkip // remote object matches local plaintext (safe to delete-if-exists)
)

// Decide uses remote identity fields (from HEAD metadata or S3VCTR01 header), never ETag.
//
// An existing object with different content is always overwritten: there is no
// "do not write" policy. The old archive.on_change switch (skip/fail) was removed
// because a global write policy is destructive for the S3 facade, which has no
// local source file to fall back on (docs/reliability-review.md H2). A guard that
// only makes sense for one command belongs on that command, not in config.
func Decide(localSHA string, localSize int64, remote domain.ObjectMeta) Action {
	if !remote.Exists {
		return ActionUpload
	}
	if remote.SHA256 != "" && remote.SHA256 == localSHA {
		if remote.ContentSize == 0 || remote.ContentSize == localSize {
			return ActionSkip
		}
	}
	return ActionUpload
}
