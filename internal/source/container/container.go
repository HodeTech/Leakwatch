// Package container provides a container image scan source.
// It pulls and inspects OCI/Docker images layer by layer without
// requiring a running Docker daemon (daemon-less, via go-containerregistry).
package container

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"log/slog"
	"path"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/HodeTech/leakwatch/internal/filter"
	"github.com/HodeTech/leakwatch/internal/source"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

const defaultMaxFileSize int64 = 10 * 1024 * 1024

// ContainerSource scans container image layers for secrets.
type ContainerSource struct {
	imageRef     string
	maxFileSize  int64
	bufferSize   int
	excludePaths []string
}

// New creates a new ContainerSource for the given image reference.
func New(imageRef string, opts ...Option) *ContainerSource {
	s := &ContainerSource{
		imageRef:    imageRef,
		maxFileSize: defaultMaxFileSize,
		bufferSize:  64,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Type returns the source type identifier.
func (s *ContainerSource) Type() string {
	return "container"
}

// Validate checks that the image reference is parseable and accessible.
func (s *ContainerSource) Validate() error {
	_, err := name.ParseReference(s.imageRef)
	if err != nil {
		return fmt.Errorf("invalid image reference %q: %w", s.imageRef, err)
	}
	return nil
}

// Chunks pulls the image and sends file contents from each layer as chunks.
func (s *ContainerSource) Chunks(ctx context.Context) <-chan source.Chunk {
	ch := make(chan source.Chunk, s.bufferSize)
	go func() {
		defer close(ch)

		ref, err := name.ParseReference(s.imageRef)
		if err != nil {
			slog.Error("failed to parse image reference", "image", s.imageRef, "error", err)
			return
		}

		img, err := remote.Image(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain), remote.WithContext(ctx))
		if err != nil {
			slog.Error("failed to pull image", "image", s.imageRef, "error", err)
			return
		}

		layers, err := img.Layers()
		if err != nil {
			slog.Error("failed to get image layers", "image", s.imageRef, "error", err)
			return
		}

		slog.Info("scanning container image", "image", s.imageRef, "layers", len(layers))

		for idx, layer := range layers {
			select {
			case <-ctx.Done():
				return
			default:
			}

			digest, err := layer.Digest()
			if err != nil {
				// Without a digest we cannot produce a meaningful layer ID
				// (digest.String() would yield ":"), so skip the layer.
				slog.Warn("failed to get layer digest, skipping layer", "layer", idx, "error", err)
				continue
			}
			layerID := digest.String()

			reader, err := layer.Uncompressed()
			if err != nil {
				slog.Warn("failed to read layer", "layer", idx, "error", err)
				continue
			}

			func() {
				defer func() { _ = reader.Close() }()
				s.scanTarLayer(ctx, ch, tar.NewReader(reader), idx, layerID)
			}()
		}

		slog.Info("container image scan completed", "image", s.imageRef)
	}()
	return ch
}

func (s *ContainerSource) scanTarLayer(ctx context.Context, ch chan<- source.Chunk, tr *tar.Reader, layerIdx int, layerID string) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			slog.Warn("failed to read tar entry", "layer", layerIdx, "error", err)
			break
		}

		// Skip directories and non-regular files.
		if header.Typeflag != tar.TypeReg {
			continue
		}

		// Skip files that are empty or exceed the size limit.
		if header.Size > s.maxFileSize || header.Size == 0 {
			continue
		}

		// Skip auto-generated lock files.
		if filter.IsSkippedFilename(header.Name) {
			continue
		}

		// Skip binary extensions.
		if filter.IsExcludedExtension(header.Name, nil) {
			continue
		}

		// Skip common non-secret paths.
		if shouldSkipContainerPath(header.Name) {
			continue
		}

		cleanPath, ok := sanitizeTarPath(header.Name)
		if !ok {
			slog.Warn("skipping tar entry with unsafe path", "path", header.Name)
			continue
		}

		// Skip files matching exclude-path globs (relative cleaned path).
		if filter.MatchesGlob(cleanPath, s.excludePaths) {
			continue
		}

		data, err := io.ReadAll(io.LimitReader(tr, s.maxFileSize))
		if err != nil {
			slog.Warn("failed to read file from layer", "file", header.Name, "layer", layerIdx, "error", err)
			continue
		}

		if filter.IsBinaryFile(data) {
			continue
		}

		select {
		case ch <- source.Chunk{
			Data: data,
			SourceMetadata: finding.SourceMetadata{
				SourceType: "container",
				Image:      s.imageRef,
				Layer:      layerID,
				LayerIdx:   layerIdx,
				FilePath:   cleanPath,
			},
		}:
		case <-ctx.Done():
			return
		}
	}
}

// sanitizeTarPath validates a tar entry name and returns a cleaned, slash-based
// relative path safe for use as a finding location. It rejects absolute paths
// and any path that escapes the archive root via a leading ".." segment.
// The boolean result is false when the entry must be skipped.
func sanitizeTarPath(name string) (string, bool) {
	// Normalize to forward slashes so segment checks are platform-independent.
	slashed := filepath.ToSlash(name)

	// Reject absolute paths (both Unix "/etc/..." and Windows "C:\...").
	if path.IsAbs(slashed) || filepath.IsAbs(name) {
		return "", false
	}

	clean := path.Clean(slashed)

	// Reject traversal: a clean path of ".." or one beginning with "../"
	// escapes the archive root.
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return "", false
	}

	return clean, true
}

// shouldSkipContainerPath returns true for paths unlikely to contain secrets.
func shouldSkipContainerPath(path string) bool {
	skipPrefixes := []string{
		"usr/share/doc/",
		"usr/share/man/",
		"usr/share/locale/",
		"usr/lib/",
		"var/cache/",
	}
	clean := strings.TrimPrefix(filepath.ToSlash(path), "/")
	for _, prefix := range skipPrefixes {
		if strings.HasPrefix(clean, prefix) {
			return true
		}
	}
	return false
}
