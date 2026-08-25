package keying

import (
	"fmt"
	"path"
	"path/filepath"
	"strings"

	"github.com/xMlex/s3vault/internal/domain"
)

// Mapper turns a local path into a stable S3 object key.
type Mapper struct {
	Prefix string
}

// Key maps absPath under root to an object key using slash separators.
func (m Mapper) Key(root, absPath string) (string, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("abs root: %w", err)
	}
	absFile, err := filepath.Abs(absPath)
	if err != nil {
		return "", fmt.Errorf("abs path: %w", err)
	}

	rel, err := filepath.Rel(absRoot, absFile)
	if err != nil {
		return "", fmt.Errorf("rel path: %w", err)
	}
	if !filepath.IsLocal(rel) {
		return "", fmt.Errorf("%w: %s", domain.ErrInvalidPath, rel)
	}

	unix := filepath.ToSlash(rel)
	if unix == "." || strings.Contains(unix, "\\") {
		return "", fmt.Errorf("%w: %s", domain.ErrInvalidPath, unix)
	}

	prefix := strings.Trim(strings.ReplaceAll(m.Prefix, "\\", "/"), "/")
	if prefix == "" {
		return unix, nil
	}
	return path.Join(prefix, unix), nil
}

const maxHTTPPath = 2048

// FromRequestPath maps GET /files/{path...} onto an object key (same prefix rules as upload).
func (m Mapper) FromRequestPath(rel string) (string, error) {
	if len(rel) > maxHTTPPath {
		return "", fmt.Errorf("%w: path too long", domain.ErrInvalidPath)
	}
	rel = strings.TrimSpace(rel)
	rel = strings.Trim(rel, "/")
	if rel == "" || strings.Contains(rel, "\\") || strings.ContainsRune(rel, 0) {
		return "", fmt.Errorf("%w: %q", domain.ErrInvalidPath, rel)
	}
	unix := path.Clean(rel)
	if unix == "." || unix == ".." || strings.HasPrefix(unix, "../") {
		return "", fmt.Errorf("%w: %s", domain.ErrInvalidPath, unix)
	}
	if !filepath.IsLocal(filepath.FromSlash(unix)) {
		return "", fmt.Errorf("%w: %s", domain.ErrInvalidPath, unix)
	}
	prefix := strings.Trim(strings.ReplaceAll(m.Prefix, "\\", "/"), "/")
	if prefix == "" {
		return unix, nil
	}
	return path.Join(prefix, unix), nil
}
