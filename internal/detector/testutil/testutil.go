// Package testutil provides shared helpers for detector tests. It exercises the
// real matcher -> Scan path so tests can prove that a detector's keywords (or
// lack thereof) actually let the matcher gate select the detector at runtime.
package testutil

import (
	"context"

	"github.com/cemililik/leakwatch/internal/detector"
	"github.com/cemililik/leakwatch/internal/matcher"
)

// ScanViaMatcher runs det through the real Aho-Corasick matcher gate before
// calling Scan, mirroring the engine pipeline. It returns the findings only if
// the matcher actually selected det for the given data; if the matcher gates the
// detector out, an empty slice is returned even when the regex would have
// matched. This makes keyword/regex misalignment visible in tests.
func ScanViaMatcher(det detector.Detector, data []byte) []detector.RawFinding {
	m := matcher.New([]detector.Detector{det})
	for _, selected := range m.Match(data) {
		if selected.ID() == det.ID() {
			return det.Scan(context.Background(), data)
		}
	}
	return nil
}
