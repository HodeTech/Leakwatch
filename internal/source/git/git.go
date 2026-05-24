// Package git provides a Git repository scan source.
package git

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/HodeTech/leakwatch/internal/filter"
	"github.com/HodeTech/leakwatch/internal/source"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

// maxSeenEntries is the upper bound for the blob deduplication map.
// When reached, deduplication is disabled to prevent unbounded memory growth.
const maxSeenEntries = 1_000_000

// GitSource is a Git repository-based scan source.
type GitSource struct {
	target         string // Local path or remote URL
	displayTarget  string // Credential-stripped form of target, safe for output/logs
	repo           *git.Repository
	bufferSize     int
	since          *time.Time
	sinceCommit    string
	branch         string
	depth          int
	maxFileSize    int64
	excludePaths   []string
	tmpDir         string // Temporary directory for cloned repos
	resolvedBranch string // Cached branch resolution
}

// New creates a new GitSource.
func New(target string, opts ...Option) *GitSource {
	s := &GitSource{
		target:        target,
		displayTarget: SafeDisplayURL(target),
		bufferSize:    64,
		maxFileSize:   10 * 1024 * 1024,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Type returns the source type.
func (s *GitSource) Type() string {
	return "git"
}

// Validate checks that the Git repository is accessible and opens/clones it.
// When --since-commit is set, it also verifies that the given commit is an
// ancestor of HEAD; otherwise the diff-based walk would silently fall back to
// scanning the entire history.
func (s *GitSource) Validate() error {
	if s.isRemote() {
		if err := s.cloneRemote(); err != nil {
			return err
		}
	} else if err := s.openLocal(); err != nil {
		return err
	}

	if s.sinceCommit != "" {
		if err := s.validateSinceCommit(); err != nil {
			return err
		}
	}

	return nil
}

// validateSinceCommit verifies that the configured since-commit exists and is
// an ancestor of HEAD. Returning an explicit error prevents the diff-based scan
// from silently degrading into a full-history scan.
func (s *GitSource) validateSinceCommit() error {
	commitHash := plumbing.NewHash(s.sinceCommit)
	sinceCommitObj, err := s.repo.CommitObject(commitHash)
	if err != nil {
		return fmt.Errorf("since-commit %q not found: %w", s.sinceCommit, err)
	}

	headRef, err := s.repo.Head()
	if err != nil {
		return fmt.Errorf("failed to resolve HEAD for since-commit check: %w", err)
	}

	headCommit, err := s.repo.CommitObject(headRef.Hash())
	if err != nil {
		return fmt.Errorf("failed to resolve HEAD commit for since-commit check: %w", err)
	}

	if sinceCommitObj.Hash == headCommit.Hash {
		return nil
	}

	isAncestor, err := sinceCommitObj.IsAncestor(headCommit)
	if err != nil {
		return fmt.Errorf("failed to check ancestry of since-commit %q: %w", s.sinceCommit, err)
	}
	if !isAncestor {
		return fmt.Errorf("since-commit %q is not an ancestor of HEAD %q", s.sinceCommit, headCommit.Hash.String())
	}

	return nil
}

// Close cleans up temporary resources. For cloned repositories, it removes
// the temporary directory.
func (s *GitSource) Close() error {
	if s.tmpDir != "" {
		if err := os.RemoveAll(s.tmpDir); err != nil {
			return fmt.Errorf("failed to remove temp directory %s: %w", s.tmpDir, err)
		}
		s.tmpDir = ""
	}
	return nil
}

func (s *GitSource) isRemote() bool {
	return strings.HasPrefix(s.target, "http://") ||
		strings.HasPrefix(s.target, "https://") ||
		strings.HasPrefix(s.target, "git@") ||
		strings.HasPrefix(s.target, "ssh://")
}

func (s *GitSource) openLocal() error {
	repo, err := git.PlainOpen(s.target)
	if err != nil {
		return fmt.Errorf("failed to open git repository %s: %w", s.target, err)
	}
	s.repo = repo
	return nil
}

func (s *GitSource) cloneRemote() error {
	tmpDir, err := os.MkdirTemp("", "leakwatch-clone-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}

	cloneOpts := &git.CloneOptions{
		URL:      s.target,
		Progress: nil,
	}

	if s.depth > 0 {
		cloneOpts.Depth = s.depth
	}

	if s.branch != "" {
		cloneOpts.ReferenceName = plumbing.NewBranchReferenceName(s.branch)
		cloneOpts.SingleBranch = true
	}

	slog.Info("cloning remote repository", "url", s.displayTarget, "tmpDir", tmpDir)

	repo, err := git.PlainClone(tmpDir, false, cloneOpts)
	if err != nil {
		_ = os.RemoveAll(tmpDir)
		return fmt.Errorf("failed to clone git repository %s: %w", s.displayTarget, err)
	}
	s.repo = repo
	s.tmpDir = tmpDir
	return nil
}

// SafeDisplayURL returns a credential-stripped form of raw that is safe to put
// in logs, output metadata, error messages, and the scan summary. Any user-info
// portion (the "user:password@" part of a URL) is removed so no secret is ever
// surfaced.
//
// The returned value is the clean URL with no noisy suffix, so it can be stored
// verbatim in a metadata field. When the URL cannot be parsed, the credential
// between "://" and "@" is masked on a best-effort basis; non-URL targets (for
// example local paths) are returned unchanged.
func SafeDisplayURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		// Best-effort: mask anything between :// and @
		if idx := strings.Index(raw, "@"); idx != -1 {
			if schemeEnd := strings.Index(raw, "://"); schemeEnd != -1 {
				return raw[:schemeEnd+3] + "***@" + raw[idx+1:]
			}
		}
		return raw
	}
	if u.User != nil {
		u.User = nil
	}
	return u.String()
}

// Chunks sends Git commit history files as chunks over a channel.
func (s *GitSource) Chunks(ctx context.Context) <-chan source.Chunk {
	ch := make(chan source.Chunk, s.bufferSize)
	go func() {
		defer close(ch)

		if s.sinceCommit != "" {
			s.chunksSinceCommit(ctx, ch)
			return
		}

		s.chunksFullHistory(ctx, ch)
	}()
	return ch
}

func (s *GitSource) chunksFullHistory(ctx context.Context, ch chan<- source.Chunk) {
	logOpts := &git.LogOptions{
		Order: git.LogOrderCommitterTime,
	}
	if s.since != nil {
		logOpts.Since = s.since
	}

	iter, err := s.repo.Log(logOpts)
	if err != nil {
		slog.Error("git log failed", "error", err)
		return
	}
	defer iter.Close()

	seen := make(map[string]bool) // blob hash -> already processed
	seenFull := false             // true when seen map hit the limit
	commitCount := 0

	err = iter.ForEach(func(c *object.Commit) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		commitCount++

		tree, err := c.Tree()
		if err != nil {
			slog.Warn("failed to get commit tree", "commit", c.Hash.String()[:8], "error", err)
			return nil
		}

		return tree.Files().ForEach(func(f *object.File) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			// Skip already-seen blobs (deduplication).
			blobKey := f.Hash.String()
			if !seenFull {
				if seen[blobKey] {
					return nil
				}
				seen[blobKey] = true
				if len(seen) >= maxSeenEntries {
					slog.Warn("blob deduplication map reached limit, disabling dedup",
						"limit", maxSeenEntries)
					seenFull = true
				}
			}

			if f.Size > s.maxFileSize {
				return nil
			}

			isBinary, _ := f.IsBinary()
			if isBinary {
				return nil
			}

			// Skip auto-generated lock files.
			if filter.IsSkippedFilename(f.Name) {
				return nil
			}

			// Skip files matching exclude-path globs (relative path).
			if filter.MatchesGlob(f.Name, s.excludePaths) {
				return nil
			}

			content, err := f.Contents()
			if err != nil {
				slog.Warn("failed to read file contents", "file", f.Name, "error", err)
				return nil
			}

			branch := s.resolveBranch()

			select {
			case ch <- source.Chunk{
				Data: []byte(content),
				SourceMetadata: finding.SourceMetadata{
					SourceType: "git",
					Repository: s.displayTarget,
					Commit:     c.Hash.String(),
					Author:     c.Author.Name,
					Email:      c.Author.Email,
					Date:       c.Author.When,
					Branch:     branch,
					FilePath:   f.Name,
				},
			}:
			case <-ctx.Done():
				return ctx.Err()
			}
			return nil
		})
	})

	if err != nil && ctx.Err() == nil {
		slog.Error("commit history scan failed", "error", err)
	}

	slog.Info("git scan completed", "commits", commitCount, "blobs", len(seen))
}

func (s *GitSource) chunksSinceCommit(ctx context.Context, ch chan<- source.Chunk) {
	commitHash := plumbing.NewHash(s.sinceCommit)
	sinceCommitObj, err := s.repo.CommitObject(commitHash)
	if err != nil {
		slog.Error("since-commit not found", "commit", s.sinceCommit, "error", err)
		return
	}

	headRef, err := s.repo.Head()
	if err != nil {
		slog.Error("failed to get HEAD reference", "error", err)
		return
	}

	headCommit, err := s.repo.CommitObject(headRef.Hash())
	if err != nil {
		slog.Error("failed to get HEAD commit", "error", err)
		return
	}

	// Scan commits between since-commit and HEAD.
	iter, err := s.repo.Log(&git.LogOptions{
		From:  headCommit.Hash,
		Order: git.LogOrderCommitterTime,
	})
	if err != nil {
		slog.Error("git log failed", "error", err)
		return
	}
	defer iter.Close()

	seen := make(map[string]bool)
	seenFull := false

	err = iter.ForEach(func(c *object.Commit) error {
		// Stop when we reach the since-commit.
		if c.Hash == sinceCommitObj.Hash {
			return io.EOF
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Get diff between this commit and its parent.
		parentTree := &object.Tree{}
		if c.NumParents() > 0 {
			parent, err := c.Parent(0)
			if err != nil {
				slog.Warn("failed to get parent commit", "commit", c.Hash.String()[:8], "error", err)
			} else {
				parentTree, _ = parent.Tree()
			}
		}

		commitTree, err := c.Tree()
		if err != nil {
			return nil
		}

		changes, err := parentTree.Diff(commitTree)
		if err != nil {
			return nil
		}

		branch := s.resolveBranch()

		for _, change := range changes {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			// Only scan added/modified files.
			if change.To.Name == "" {
				continue // Deleted file
			}

			blobKey := change.To.TreeEntry.Hash.String()
			if !seenFull {
				if seen[blobKey] {
					continue
				}
				seen[blobKey] = true
				if len(seen) >= maxSeenEntries {
					slog.Warn("blob deduplication map reached limit, disabling dedup",
						"limit", maxSeenEntries)
					seenFull = true
				}
			}

			file, err := commitTree.File(change.To.Name)
			if err != nil {
				continue
			}

			if file.Size > s.maxFileSize {
				continue
			}

			isBinary, _ := file.IsBinary()
			if isBinary {
				continue
			}

			if filter.IsSkippedFilename(change.To.Name) {
				continue
			}

			// Skip files matching exclude-path globs (relative path).
			if filter.MatchesGlob(change.To.Name, s.excludePaths) {
				continue
			}

			content, err := file.Contents()
			if err != nil {
				slog.Warn("failed to read file contents", "file", change.To.Name, "error", err)
				continue
			}

			select {
			case ch <- source.Chunk{
				Data: []byte(content),
				SourceMetadata: finding.SourceMetadata{
					SourceType: "git",
					Repository: s.displayTarget,
					Commit:     c.Hash.String(),
					Author:     c.Author.Name,
					Email:      c.Author.Email,
					Date:       c.Author.When,
					Branch:     branch,
					FilePath:   change.To.Name,
				},
			}:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	})

	if err != nil && err != io.EOF && ctx.Err() == nil {
		slog.Error("diff-based scan failed", "error", err)
	}
}

// resolveBranch returns the current branch name, caching the result after
// the first resolution to avoid repeated Head() calls.
func (s *GitSource) resolveBranch() string {
	if s.branch != "" {
		return s.branch
	}
	if s.resolvedBranch != "" {
		return s.resolvedBranch
	}
	headRef, err := s.repo.Head()
	if err != nil {
		return ""
	}
	s.resolvedBranch = headRef.Name().Short()
	return s.resolvedBranch
}
