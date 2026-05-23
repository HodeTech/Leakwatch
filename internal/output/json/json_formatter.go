// Package json provides a JSON output formatter.
package json

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/cemililik/leakwatch/pkg/finding"
)

// Formatter outputs findings in JSON format.
type Formatter struct {
	// ShowRaw controls whether the raw secret value is included in output.
	// finding.Finding.Raw carries a json:"-" tag, so it is never serialized by
	// default. When ShowRaw is true, each finding is marshaled through the
	// findingJSON wire type below to explicitly opt the value back in.
	ShowRaw bool
}

// findingJSON is the wire type used to opt the raw secret value back into JSON
// output when ShowRaw is enabled. It embeds finding.Finding (whose Raw field is
// json:"-") and re-adds a "raw" field that mirrors finding.Finding.Raw.
type findingJSON struct {
	finding.Finding
	Raw string `json:"raw,omitempty"`
}

// Format writes findings as JSON to the given writer.
// When ShowRaw is false, finding.Finding is marshaled directly and the raw
// secret is omitted by its json:"-" tag. When ShowRaw is true, each finding is
// marshaled via findingJSON so the raw value is explicitly included.
func (f *Formatter) Format(w io.Writer, findings []finding.Finding) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")

	if !f.ShowRaw {
		if err := encoder.Encode(findings); err != nil {
			return fmt.Errorf("failed to write JSON output: %w", err)
		}
		return nil
	}

	output := make([]findingJSON, len(findings))
	for i, fd := range findings {
		output[i] = findingJSON{Finding: fd, Raw: fd.Raw}
	}
	if err := encoder.Encode(output); err != nil {
		return fmt.Errorf("failed to write JSON output: %w", err)
	}
	return nil
}

// FileExtension returns the JSON file extension.
func (f *Formatter) FileExtension() string {
	return ".json"
}
