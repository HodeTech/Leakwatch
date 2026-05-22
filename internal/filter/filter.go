// Package filter provides file filtering helpers.
package filter

import (
	"log/slog"
	"path/filepath"
	"strings"
)

const (
	// binaryCheckLen is the number of bytes to inspect for null bytes.
	binaryCheckLen = 8192
)

// defaultBinaryExtensions lists file extensions that are always skipped.
var defaultBinaryExtensions = map[string]bool{
	".exe": true, ".dll": true, ".so": true, ".dylib": true,
	".bin": true, ".o": true, ".a": true,
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
	".bmp": true, ".ico": true, ".svg": true, ".webp": true,
	".mp3": true, ".mp4": true, ".avi": true, ".mov": true,
	".zip": true, ".tar": true, ".gz": true, ".bz2": true,
	".rar": true, ".7z": true, ".xz": true,
	".pdf": true, ".woff": true, ".woff2": true, ".ttf": true, ".eot": true,
}

// defaultSkipFilenames lists filenames that are always skipped.
// These are auto-generated files that contain hashes/checksums
// which frequently trigger false positives.
var defaultSkipFilenames = map[string]bool{
	"package-lock.json": true,
	"yarn.lock":         true,
	"pnpm-lock.yaml":    true,
	"composer.lock":     true,
	"Gemfile.lock":      true,
	"Cargo.lock":        true,
	"poetry.lock":       true,
	"go.sum":            true,
	"Pipfile.lock":      true,
}

// IsSkippedFilename checks whether a filename should be skipped.
func IsSkippedFilename(path string) bool {
	return defaultSkipFilenames[filepath.Base(path)]
}

// IsExcludedExtension checks whether a file extension should be excluded.
func IsExcludedExtension(path string, extraExts []string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	if defaultBinaryExtensions[ext] {
		return true
	}
	for _, e := range extraExts {
		if strings.EqualFold(ext, e) {
			return true
		}
	}
	return false
}

// IsBinaryFile checks whether data appears to be a binary file.
// If a null byte is found within the first 8KB, it is considered binary.
func IsBinaryFile(data []byte) bool {
	checkLen := binaryCheckLen
	if len(data) < checkLen {
		checkLen = len(data)
	}
	for i := 0; i < checkLen; i++ {
		if data[i] == 0 {
			return true
		}
	}
	return false
}

// MatchesGlob reports whether path matches any of the given glob patterns.
// It supports three pattern styles:
//   - standard filepath.Match globs (e.g. "*.yaml"), tried against both the full
//     path and the base filename so simple patterns match nested files;
//   - "**" (double-star) patterns matched segment-by-segment so "**" spans zero
//     or more directory segments;
//   - gitignore-style directory patterns with a trailing slash (e.g. "build/"),
//     which match every path inside a directory of that name at any depth.
//
// A pattern with invalid glob syntax never matches: filepath.Match's error is
// logged at debug level and treated as a non-match, so one malformed exclude
// pattern cannot abort filtering. (Previously the doc claimed an error was
// returned, which the bool signature could not honor — CFG-m-03.)
func MatchesGlob(path string, patterns []string) bool {
	for _, pattern := range patterns {
		if matchGlob(pattern, path) {
			return true
		}
		// Also match against the base filename for simple patterns.
		if matchGlob(pattern, filepath.Base(path)) {
			return true
		}
	}
	return false
}

// matchGlob matches a single pattern against a path, supporting ** (double-star)
// and gitignore-style trailing-slash directory patterns. Invalid patterns are
// logged and treated as non-matches.
func matchGlob(pattern, path string) bool {
	// gitignore-style "dir/" matches the whole subtree of a directory named
	// "dir" at any depth (e.g. "build/" matches "build/x" and "src/build/x").
	if trimmed, ok := strings.CutSuffix(pattern, "/"); ok && trimmed != "" && !strings.Contains(trimmed, "**") {
		return matchDirPrefix(trimmed, path)
	}

	// If pattern contains **, use segment-based matching.
	if strings.Contains(pattern, "**") {
		return matchDoubleStar(pattern, path)
	}

	matched, err := filepath.Match(pattern, path)
	if err != nil {
		slog.Debug("ignoring invalid glob pattern", "pattern", pattern, "error", err)
		return false
	}
	return matched
}

// matchDirPrefix reports whether path lies within a directory matching dirPattern
// at any depth, implementing gitignore-style "dir/" semantics. Each path segment
// except the last (the filename) is tested against dirPattern with
// filepath.Match, so simple globs like "build*/" also work.
func matchDirPrefix(dirPattern, path string) bool {
	segments := splitPath(path)
	// The trailing segment is the file itself; a directory pattern only matches
	// when there is at least one segment after the matched directory.
	for i := 0; i < len(segments)-1; i++ {
		matched, err := filepath.Match(dirPattern, segments[i])
		if err != nil {
			slog.Debug("ignoring invalid glob pattern", "pattern", dirPattern+"/", "error", err)
			return false
		}
		if matched {
			return true
		}
	}
	return false
}

// matchDoubleStar handles ** glob patterns.
// ** matches zero or more directory segments.
func matchDoubleStar(pattern, path string) bool {
	// Split both on separator
	patternParts := splitPath(pattern)
	pathParts := splitPath(path)
	return matchSegments(patternParts, pathParts)
}

func matchSegments(pattern, path []string) bool {
	// Base cases
	if len(pattern) == 0 {
		return len(path) == 0
	}

	head := pattern[0]
	rest := pattern[1:]

	if head == "**" {
		// ** matches zero or more segments
		// Try matching rest of pattern from every position in path
		for i := 0; i <= len(path); i++ {
			if matchSegments(rest, path[i:]) {
				return true
			}
		}
		return false
	}

	if len(path) == 0 {
		return false
	}

	matched, _ := filepath.Match(head, path[0])
	if !matched {
		return false
	}
	return matchSegments(rest, path[1:])
}

func splitPath(p string) []string {
	// Normalize separators
	p = filepath.ToSlash(p)
	parts := strings.Split(p, "/")
	// Remove empty parts
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}
