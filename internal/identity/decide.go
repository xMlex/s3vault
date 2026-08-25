package identity

import "github.com/xMlex/s3vault/internal/domain"

// OnChange is what to do when a remote object exists but content differs.
type OnChange int

const (
	OnChangeUnknown OnChange = iota
	OnChangeOverwrite
	OnChangeSkip
	OnChangeFail
)

// Action is the upload pipeline decision for one file.
type Action int

const (
	ActionUnknown Action = iota
	ActionUpload
	ActionSkip // remote object matches local plaintext (safe to delete-if-exists)
	ActionFail
	// ActionOmit: remote exists with different content and on_change=skip.
	// Do not delete the local file — it is the only copy of the new bytes.
	ActionOmit
)

// ParseOnChange maps config strings to OnChange.
func ParseOnChange(s string) (OnChange, bool) {
	switch s {
	case "overwrite":
		return OnChangeOverwrite, true
	case "skip":
		return OnChangeSkip, true
	case "fail":
		return OnChangeFail, true
	default:
		return OnChangeUnknown, false
	}
}

// Decide uses remote identity fields (from HEAD metadata or S3VCTR01 header), never ETag.
func Decide(localSHA string, localSize int64, remote domain.ObjectMeta, onChange OnChange) Action {
	if !remote.Exists {
		return ActionUpload
	}
	if remote.SHA256 != "" && remote.SHA256 == localSHA {
		if remote.ContentSize == 0 || remote.ContentSize == localSize {
			return ActionSkip
		}
	}
	switch onChange {
	case OnChangeSkip:
		return ActionOmit
	case OnChangeFail:
		return ActionFail
	default:
		return ActionUpload
	}
}
