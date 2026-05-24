// Package output defines output formatter interfaces.
package output

import (
	"io"

	"github.com/HodeTech/leakwatch/pkg/finding"
)

// Formatter outputs findings in a specific format.
type Formatter interface {
	// Format writes findings to the given writer.
	Format(w io.Writer, findings []finding.Finding) error

	// FileExtension returns the file extension for this format.
	FileExtension() string
}
