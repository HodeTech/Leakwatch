// Package source defines scan source interfaces.
package source

import (
	"context"

	"github.com/HodeTech/leakwatch/pkg/finding"
)

// Source represents a data source to be scanned.
// Each source type (Git, filesystem, container) implements this interface.
type Source interface {
	// Type returns the source type identifier (e.g., "git", "filesystem", "container").
	Type() string

	// Chunks sends scannable data chunks over a channel.
	// The channel is closed when the context is cancelled.
	Chunks(ctx context.Context) <-chan Chunk

	// Validate checks that the source is accessible and valid.
	Validate() error
}

// Chunk is the smallest unit of data to be scanned.
type Chunk struct {
	// Data is the raw content to scan.
	Data []byte

	// SourceMetadata describes where the chunk originated from.
	SourceMetadata finding.SourceMetadata
}
