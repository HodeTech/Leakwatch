// Package filesystem provides a filesystem-based scan source.
package filesystem

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/HodeTech/leakwatch/internal/filter"
	"github.com/HodeTech/leakwatch/internal/source"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

// defaultMaxFileSize is the maximum file size to scan (10 MB).
const defaultMaxFileSize int64 = 10 * 1024 * 1024

// FilesystemSource is a filesystem-based scan source.
type FilesystemSource struct {
	root         string
	maxFileSize  int64
	excludeExts  []string
	excludePaths []string
	bufferSize   int
}

// New creates a new FilesystemSource. The root path is cleaned and
// resolved to an absolute path.
func New(root string, opts ...Option) *FilesystemSource {
	cleanRoot := filepath.Clean(root)
	absRoot, err := filepath.Abs(cleanRoot)
	if err != nil {
		absRoot = cleanRoot
	}

	s := &FilesystemSource{
		root:        absRoot,
		maxFileSize: defaultMaxFileSize,
		bufferSize:  64,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Type returns the source type.
func (s *FilesystemSource) Type() string {
	return "filesystem"
}

// Validate checks that the root directory exists and is readable.
func (s *FilesystemSource) Validate() error {
	info, err := os.Stat(s.root)
	if err != nil {
		return fmt.Errorf("source directory inaccessible %s: %w", s.root, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("source is not a directory: %s", s.root)
	}
	return nil
}

// Chunks walks the filesystem and sends chunks over a channel.
func (s *FilesystemSource) Chunks(ctx context.Context) <-chan source.Chunk {
	ch := make(chan source.Chunk, s.bufferSize)
	go func() {
		defer close(ch)
		err := filepath.WalkDir(s.root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				slog.Warn("directory read error", "path", path, "error", err)
				return nil
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			// Skip symlinks to avoid cycles and potential security issues.
			if d.Type()&fs.ModeSymlink != 0 {
				return nil
			}

			if d.IsDir() {
				return nil
			}

			if s.shouldSkip(path, d) {
				return nil
			}

			data, err := os.ReadFile(path)
			if err != nil {
				slog.Warn("file read error", "path", path, "error", err)
				return nil
			}

			if filter.IsBinaryFile(data) {
				return nil
			}

			relPath, err := filepath.Rel(s.root, path)
			if err != nil {
				relPath = path
			}

			select {
			case ch <- source.Chunk{
				Data: data,
				SourceMetadata: finding.SourceMetadata{
					SourceType: "filesystem",
					FilePath:   relPath,
				},
			}:
			case <-ctx.Done():
				return ctx.Err()
			}
			return nil
		})
		if err != nil && ctx.Err() == nil {
			slog.Error("filesystem scan failed", "error", err)
		}
	}()
	return ch
}

func (s *FilesystemSource) shouldSkip(path string, d fs.DirEntry) bool {
	// Skip auto-generated lock files (contain hashes that trigger false positives).
	if filter.IsSkippedFilename(path) {
		return true
	}

	// Extension check
	if filter.IsExcludedExtension(path, s.excludeExts) {
		return true
	}

	// Exclude path patterns
	relPath, err := filepath.Rel(s.root, path)
	if err == nil && filter.MatchesGlob(relPath, s.excludePaths) {
		return true
	}

	// File size check
	info, err := d.Info()
	if err != nil {
		return true
	}
	if info.Size() > s.maxFileSize || info.Size() == 0 {
		return true
	}

	return false
}
