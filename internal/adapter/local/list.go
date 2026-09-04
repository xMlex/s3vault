package localstore

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"

	"github.com/xMlex/s3vault/internal/domain"
)

// maxKeysCap matches the ListObjectsV2 default and hard limit.
const maxKeysCap = 1000

// List returns one page of objects, ordered by key like ListObjectsV2.
//
// The whole tree under Prefix is walked and sorted on every call, so cost is
// linear in the number of stored objects.
func (s *Store) List(ctx context.Context, opts domain.ListOptions) (domain.ListPage, error) {
	entries, err := s.walk(ctx, opts.Prefix)
	if err != nil {
		return domain.ListPage{}, err
	}
	slices.SortFunc(entries, func(a, b domain.ListObject) int {
		return strings.Compare(a.Key, b.Key)
	})

	limit := int(opts.MaxKeys)
	if limit <= 0 || limit > maxKeysCap {
		limit = maxKeysCap
	}

	var (
		page      domain.ListPage
		groups    = make(map[string]struct{})
		count     int
		truncated bool
		lastMark  string
	)
	for _, e := range entries {
		if opts.StartAfter != "" && e.Key <= opts.StartAfter {
			continue
		}
		// mark is what a continuation token points at: the common prefix for
		// grouped keys, the key itself otherwise. Resuming therefore skips a
		// whole group at once and never repeats a prefix.
		mark := e.Key
		group := commonPrefix(e.Key, opts.Prefix, opts.Delimiter)
		if group != "" {
			mark = group
		}
		if opts.ContinuationToken != "" && mark <= opts.ContinuationToken {
			continue
		}
		if group != "" {
			if _, seen := groups[group]; seen {
				continue
			}
			if count == limit {
				truncated = true
				break
			}
			groups[group] = struct{}{}
			page.CommonPrefixes = append(page.CommonPrefixes, group)
		} else {
			if count == limit {
				truncated = true
				break
			}
			page.Contents = append(page.Contents, e)
		}
		count++
		lastMark = mark
	}
	page.KeyCount = int32(count)
	page.IsTruncated = truncated
	if truncated {
		page.NextContinuationToken = lastMark
	}
	return page, nil
}

// commonPrefix returns the delimiter-terminated group a key belongs to, or "".
func commonPrefix(key, prefix, delimiter string) string {
	if delimiter == "" {
		return ""
	}
	rest := strings.TrimPrefix(key, prefix)
	i := strings.Index(rest, delimiter)
	if i < 0 {
		return ""
	}
	return prefix + rest[:i+len(delimiter)]
}

func (s *Store) walk(ctx context.Context, prefix string) ([]domain.ListObject, error) {
	var out []domain.ListObject
	err := fs.WalkDir(s.root.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if d.IsDir() {
			if p == "." {
				return nil
			}
			if p == tmpDir || !dirCanMatch(p, prefix) {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || !strings.HasPrefix(p, prefix) {
			return nil
		}
		if strings.HasSuffix(p, metaSuffix) {
			return nil // layout=raw identity sidecar
		}
		fi, err := d.Info()
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil // concurrent Delete
			}
			return err
		}
		out = append(out, domain.ListObject{
			Key:          p,
			Size:         fi.Size(),
			ETag:         etag(fi),
			LastModified: fi.ModTime().UTC(),
		})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list: %w", err)
	}
	return out, nil
}

// dirCanMatch reports whether a directory may hold keys under prefix.
func dirCanMatch(dir, prefix string) bool {
	if prefix == "" {
		return true
	}
	dir += "/"
	return strings.HasPrefix(dir, prefix) || strings.HasPrefix(prefix, dir)
}
