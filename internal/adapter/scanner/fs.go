package scanner

import (
	"context"
	"fmt"
	"io/fs"
	"iter"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/xMlex/s3vault/internal/domain"
	"github.com/xMlex/s3vault/internal/port"
)

// Options control how the filesystem is walked.
type Options struct {
	FollowSymlinks bool
	Logger         *slog.Logger
}

// FS walks a directory tree. Directories are never emitted.
type FS struct {
	opts Options
}

var _ port.Scanner = (*FS)(nil)

// New returns a filesystem scanner.
func New(opts Options) *FS {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	return &FS{opts: opts}
}

// Stat returns a single regular file under root. Unlike Scan it does not filter
// by mtime. Unfollowed symlinks and non-regular files are errors.
func (s *FS) Stat(root, name string) (domain.FileInfo, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return domain.FileInfo{}, fmt.Errorf("abs root: %w", err)
	}
	absPath, err := filepath.Abs(name)
	if err != nil {
		return domain.FileInfo{}, fmt.Errorf("abs path: %w", err)
	}
	st, err := os.Lstat(absPath)
	if err != nil {
		return domain.FileInfo{}, fmt.Errorf("stat %s: %w", absPath, err)
	}
	if st.Mode()&fs.ModeSymlink != 0 {
		if !s.opts.FollowSymlinks {
			return domain.FileInfo{}, fmt.Errorf("%w: %s", domain.ErrSymlinkSkipped, absPath)
		}
		info, skip, err := s.followSymlink(absRoot, absPath)
		if err != nil {
			return domain.FileInfo{}, err
		}
		if skip {
			return domain.FileInfo{}, fmt.Errorf("%w: %s", domain.ErrNotRegularFile, absPath)
		}
		return info, nil
	}
	if !st.Mode().IsRegular() {
		return domain.FileInfo{}, fmt.Errorf("%w: %s", domain.ErrNotRegularFile, absPath)
	}
	rel, err := relLocal(absRoot, absPath)
	if err != nil {
		return domain.FileInfo{}, err
	}
	return domain.FileInfo{
		AbsPath: absPath,
		RelPath: rel,
		Size:    st.Size(),
		ModTime: st.ModTime(),
	}, nil
}

// Scan yields regular files whose mtime is strictly older than now-olderThan.
func (s *FS) Scan(ctx context.Context, root string, olderThan time.Duration) iter.Seq2[domain.FileInfo, error] {
	return func(yield func(domain.FileInfo, error) bool) {
		absRoot, err := filepath.Abs(root)
		if err != nil {
			yield(domain.FileInfo{}, fmt.Errorf("abs root: %w", err))
			return
		}
		cutoff := time.Now().Add(-olderThan)

		err = filepath.WalkDir(absRoot, func(path string, d fs.DirEntry, walkErr error) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if walkErr != nil {
				if !yield(domain.FileInfo{}, fmt.Errorf("walk %s: %w", path, walkErr)) {
					return fs.SkipAll
				}
				return nil
			}
			if d.IsDir() {
				return nil
			}

			info, skip, err := s.fileInfo(absRoot, path, d)
			if err != nil {
				if !yield(domain.FileInfo{}, err) {
					return fs.SkipAll
				}
				return nil
			}
			if skip {
				return nil
			}
			if !info.ModTime.Before(cutoff) {
				return nil
			}
			if !yield(info, nil) {
				return fs.SkipAll
			}
			return nil
		})
		if err != nil && ctx.Err() == nil {
			yield(domain.FileInfo{}, err)
		}
	}
}

func (s *FS) fileInfo(absRoot, path string, d fs.DirEntry) (domain.FileInfo, bool, error) {
	mode := d.Type()
	if mode&fs.ModeSymlink != 0 {
		if !s.opts.FollowSymlinks {
			s.opts.Logger.Warn("skipping symlink", slog.String("path", path))
			return domain.FileInfo{}, true, nil
		}
		return s.followSymlink(absRoot, path)
	}
	if !mode.IsRegular() {
		s.opts.Logger.Debug("skipping non-regular file", slog.String("path", path))
		return domain.FileInfo{}, true, nil
	}

	st, err := d.Info()
	if err != nil {
		return domain.FileInfo{}, false, fmt.Errorf("stat %s: %w", path, err)
	}
	rel, err := relLocal(absRoot, path)
	if err != nil {
		return domain.FileInfo{}, false, err
	}
	return domain.FileInfo{
		AbsPath: path,
		RelPath: rel,
		Size:    st.Size(),
		ModTime: st.ModTime(),
	}, false, nil
}

func (s *FS) followSymlink(absRoot, path string) (domain.FileInfo, bool, error) {
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		return domain.FileInfo{}, false, fmt.Errorf("eval symlink %s: %w", path, err)
	}
	resolvedRoot, err := filepath.EvalSymlinks(absRoot)
	if err != nil {
		resolvedRoot = absRoot
	}
	if _, err := relLocal(resolvedRoot, target); err != nil {
		return domain.FileInfo{}, false, fmt.Errorf("%w: %s -> %s", domain.ErrSymlinkEscape, path, target)
	}
	st, err := os.Stat(target)
	if err != nil {
		return domain.FileInfo{}, false, fmt.Errorf("stat symlink target %s: %w", target, err)
	}
	if !st.Mode().IsRegular() {
		s.opts.Logger.Warn("skipping symlink to non-regular file", slog.String("path", path))
		return domain.FileInfo{}, true, nil
	}
	rel, err := relLocal(absRoot, path)
	if err != nil {
		return domain.FileInfo{}, false, err
	}
	return domain.FileInfo{
		AbsPath: target,
		RelPath: rel,
		Size:    st.Size(),
		ModTime: st.ModTime(),
	}, false, nil
}

func relLocal(root, path string) (string, error) {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return "", fmt.Errorf("rel %s: %w", path, err)
	}
	if !filepath.IsLocal(rel) {
		return "", fmt.Errorf("%w: %s", domain.ErrInvalidPath, rel)
	}
	return filepath.ToSlash(rel), nil
}
