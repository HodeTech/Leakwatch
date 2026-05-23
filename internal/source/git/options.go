package git

import "time"

// Option configures a GitSource.
type Option func(*GitSource)

// WithSince scans only commits after the specified date.
func WithSince(t time.Time) Option {
	return func(s *GitSource) {
		s.since = &t
	}
}

// WithSinceCommit scans only changes from the specified commit to HEAD.
func WithSinceCommit(hash string) Option {
	return func(s *GitSource) {
		s.sinceCommit = hash
	}
}

// WithBranch scans only the specified branch.
func WithBranch(branch string) Option {
	return func(s *GitSource) {
		s.branch = branch
	}
}

// WithDepth sets the clone depth (remote repositories only).
func WithDepth(depth int) Option {
	return func(s *GitSource) {
		s.depth = depth
	}
}

// WithMaxFileSize sets the maximum file size to scan.
func WithMaxFileSize(size int64) Option {
	return func(s *GitSource) {
		s.maxFileSize = size
	}
}

// WithBufferSize sets the chunk channel buffer size.
func WithBufferSize(size int) Option {
	return func(s *GitSource) {
		s.bufferSize = size
	}
}

// WithExcludePaths sets glob patterns for file paths to exclude from scanning.
// Patterns are matched against each file's path within the repository,
// mirroring filesystem.WithExcludePaths semantics.
func WithExcludePaths(patterns []string) Option {
	return func(s *GitSource) {
		s.excludePaths = patterns
	}
}
