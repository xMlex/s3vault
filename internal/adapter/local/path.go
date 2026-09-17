package localstore

import (
	"fmt"
	"path"
	"path/filepath"
	"strings"

	"github.com/xMlex/s3vault/internal/domain"
)

// tmpDir holds partially written objects; it is never listed and never
// reachable through an object key.
const tmpDir = ".s3vault-tmp"

// relPath maps an object key to a path relative to the store root.
//
// Only keys that survive round-tripping through path.Clean are accepted, so
// "..", "//" and "./" never reach the filesystem. os.Root enforces the same
// boundary at syscall level; this check keeps the error message useful.
func relPath(key string) (string, error) {
	switch {
	case key == "",
		strings.HasPrefix(key, "/"),
		strings.HasSuffix(key, "/"),
		strings.ContainsAny(key, `\`+"\x00"),
		key != path.Clean(key):
		return "", fmt.Errorf("%w: object key %q", domain.ErrInvalidPath, key)
	}
	if key == tmpDir || strings.HasPrefix(key, tmpDir+"/") {
		return "", fmt.Errorf("%w: object key %q is reserved", domain.ErrInvalidPath, key)
	}
	rel := filepath.FromSlash(key)
	if !filepath.IsLocal(rel) {
		return "", fmt.Errorf("%w: object key %q", domain.ErrInvalidPath, key)
	}
	return rel, nil
}
