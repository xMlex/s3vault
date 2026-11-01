package localstore

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
)

// Delete removes an object. Deleting a missing key succeeds, as in S3.
func (s *Store) Delete(ctx context.Context, key string) error {
	rel, err := relPath(key)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.root.Remove(rel); err != nil {
		if !isNotFound(err) {
			return fmt.Errorf("delete %s: %w", key, err)
		}
	}

	s.forgetDigest(key, rel)
	s.pruneDirs(filepath.Dir(rel))
	return nil
}

// pruneDirs drops directories left empty by Delete. Remove fails on a
// non-empty directory, which ends the walk upwards.
//
// Only a directory is removed. S3 has no hierarchy: "a" and "a/b" are separate
// objects, so the component above a deleted key may itself be a file object
// ("DELETE a/b" when only "a" exists is an idempotent no-op). Removing that
// component would delete a live object.
func (s *Store) pruneDirs(dir string) {
	for dir != "." && dir != string(filepath.Separator) && dir != "" {
		fi, err := s.root.Lstat(dir)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			// Nothing to remove here; its parents may still be empty.
		case err != nil:
			return
		case !fi.IsDir():
			return
		default:
			if err := s.root.Remove(dir); err != nil {
				return
			}
		}
		dir = filepath.Dir(dir)
	}
}
