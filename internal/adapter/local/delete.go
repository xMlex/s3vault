package localstore

import (
	"context"
	"fmt"
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
	s.pruneDirs(filepath.Dir(rel))
	return nil
}

// pruneDirs drops directories left empty by Delete. Remove fails on a
// non-empty directory, which ends the walk upwards.
func (s *Store) pruneDirs(dir string) {
	for dir != "." && dir != string(filepath.Separator) && dir != "" {
		if err := s.root.Remove(dir); err != nil {
			return
		}
		dir = filepath.Dir(dir)
	}
}
