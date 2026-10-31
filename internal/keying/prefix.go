package keying

import (
	"fmt"
	"path"
	"path/filepath"
	"strings"

	"github.com/xMlex/s3vault/internal/domain"
)

// ValidateRelative cleans a client-supplied key or list prefix and refuses
// anything that could escape the key space: backslashes, NUL, empty values and
// path traversal. The returned value is the canonical slash-separated form.
//
// It deliberately does no prefix joining. Callers that own a prefix must join
// only after this check, so "a/../b" can never become "b" and leave the
// user's namespace.
func ValidateRelative(rel string) (string, error) {
	rel = strings.TrimSpace(rel)
	rel = strings.Trim(rel, "/")

	if rel == "" {
		return "", fmt.Errorf("%w: empty", domain.ErrInvalidPath)
	}

	if len(rel) > maxHTTPPath {
		return "", fmt.Errorf("%w: path too long", domain.ErrInvalidPath)
	}

	if strings.ContainsRune(rel, 0) || strings.ContainsRune(rel, '\\') {
		return "", fmt.Errorf("%w: %q", domain.ErrInvalidPath, rel)
	}

	unix := path.Clean(rel)
	if unix == "." || unix == ".." || strings.HasPrefix(unix, "../") {
		return "", fmt.Errorf("%w: %s", domain.ErrInvalidPath, unix)
	}

	if !filepath.IsLocal(filepath.FromSlash(unix)) {
		return "", fmt.Errorf("%w: %s", domain.ErrInvalidPath, unix)
	}

	return unix, nil
}

// NormalizePrefix canonicalises a user's transparent prefix: no surrounding
// spaces or slashes, no empty segments, no "." or "..". A valid prefix is never
// empty; an empty prefix would give the user the whole storage namespace.
func NormalizePrefix(prefix string) (string, error) {
	prefix = strings.TrimSpace(prefix)
	prefix = strings.Trim(prefix, "/")

	if prefix == "" {
		return "", fmt.Errorf("%w: empty prefix", domain.ErrInvalidPath)
	}

	if len(prefix) > maxHTTPPath {
		return "", fmt.Errorf("%w: prefix too long", domain.ErrInvalidPath)
	}

	if strings.ContainsRune(prefix, 0) || strings.ContainsRune(prefix, '\\') {
		return "", fmt.Errorf("%w: %q", domain.ErrInvalidPath, prefix)
	}

	for seg := range strings.SplitSeq(prefix, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return "", fmt.Errorf("%w: %q", domain.ErrInvalidPath, prefix)
		}
	}

	return prefix, nil
}

// JoinPrefix joins a storage-wide prefix and a user prefix. Either may be
// empty; the result is canonical.
func JoinPrefix(global, user string) string {
	global = strings.Trim(strings.ReplaceAll(global, "\\", "/"), "/")
	user = strings.Trim(strings.ReplaceAll(user, "\\", "/"), "/")

	switch {
	case global == "":
		return user
	case user == "":
		return global
	default:
		return path.Join(global, user)
	}
}

// NormalizeOptionalPrefix canonicalises a prefix that may be absent. Empty is
// valid; anything else must satisfy NormalizePrefix.
func NormalizeOptionalPrefix(prefix string) (string, error) {
	trimmed := strings.Trim(strings.TrimSpace(prefix), "/")
	if trimmed == "" {
		return "", nil
	}

	return NormalizePrefix(trimmed)
}

// IsCanonicalOptionalPrefix reports whether prefix is already in
// NormalizeOptionalPrefix form.
func IsCanonicalOptionalPrefix(prefix string) bool {
	normalized, err := NormalizeOptionalPrefix(prefix)

	return err == nil && normalized == prefix
}

// PrefixesOverlap reports whether two canonical prefixes share a namespace,
// comparing whole segments. "a" and "ab" do not overlap; "a" and "a/b" do.
func PrefixesOverlap(a, b string) bool {
	if a == "" || b == "" {
		return a == b
	}

	return a == b ||
		strings.HasPrefix(a, b+"/") ||
		strings.HasPrefix(b, a+"/")
}

// IsCanonicalPrefix reports whether prefix is already in NormalizePrefix form.
func IsCanonicalPrefix(prefix string) bool {
	normalized, err := NormalizePrefix(prefix)

	return err == nil && normalized == prefix
}
