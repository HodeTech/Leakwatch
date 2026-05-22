package filter

import (
	"testing"

	"github.com/cemililik/leakwatch/pkg/finding"
)

func TestHasInlineIgnore_GenericMarker_ReturnsTrue(t *testing.T) {
	line := `API_KEY = "AKIA1234EXAMPLE567890"  # leakwatch:ignore`
	if !HasInlineIgnore(line) {
		t.Error("expected HasInlineIgnore to return true for generic marker")
	}
}

func TestHasInlineIgnore_NoMarker_ReturnsFalse(t *testing.T) {
	line := `API_KEY = "AKIA1234EXAMPLE567890"  # some other comment`
	if HasInlineIgnore(line) {
		t.Error("expected HasInlineIgnore to return false when no marker present")
	}
}

func TestHasInlineIgnoreForDetector_SpecificDetector_ReturnsTrue(t *testing.T) {
	line := `PASSWORD = "test123"  # leakwatch:ignore:aws-access-key-id`
	if !HasInlineIgnoreForDetector(line, "aws-access-key-id") {
		t.Error("expected true for matching detector ID")
	}
}

func TestHasInlineIgnoreForDetector_GenericMarker_ReturnsTrue(t *testing.T) {
	line := `API_KEY = "AKIA1234EXAMPLE567890"  # leakwatch:ignore`
	if !HasInlineIgnoreForDetector(line, "aws-access-key-id") {
		t.Error("expected true for generic marker regardless of detector ID")
	}
}

func TestHasInlineIgnoreForDetector_DifferentDetector_ReturnsFalse(t *testing.T) {
	line := `PASSWORD = "test123"  # leakwatch:ignore:aws-access-key-id`
	if HasInlineIgnoreForDetector(line, "github-token") {
		t.Error("expected false for non-matching detector ID")
	}
}

func TestHasInlineIgnoreForDetector_NoMarker_ReturnsFalse(t *testing.T) {
	line := `PASSWORD = "test123"  # safe value`
	if HasInlineIgnoreForDetector(line, "aws-access-key-id") {
		t.Error("expected false when no ignore marker present")
	}
}

func TestFilterFindingsByInlineIgnore_RemovesIgnoredFindings(t *testing.T) {
	sourceContent := []byte("line1\nAPI_KEY = \"AKIAEXAMPLE\" # leakwatch:ignore\nline3\nSECRET = \"s3cr3t\" # leakwatch:ignore:generic-secret\nline5\n")

	findings := []finding.Finding{
		{
			DetectorID: "aws-access-key-id",
			SourceMetadata: finding.SourceMetadata{
				FilePath: "config.py",
				Line:     2,
			},
		},
		{
			DetectorID: "generic-secret",
			SourceMetadata: finding.SourceMetadata{
				FilePath: "config.py",
				Line:     4,
			},
		},
		{
			DetectorID: "aws-secret-key",
			SourceMetadata: finding.SourceMetadata{
				FilePath: "config.py",
				Line:     5,
			},
		},
	}

	sourceData := map[string][]byte{
		"config.py": sourceContent,
	}

	result := FilterFindingsByInlineIgnore(findings, sourceData)

	if len(result) != 1 {
		t.Fatalf("expected 1 finding after filtering, got %d", len(result))
	}
	if result[0].DetectorID != "aws-secret-key" {
		t.Errorf("expected remaining finding to be aws-secret-key, got %q", result[0].DetectorID)
	}
}

func TestFilterFindingsByInlineIgnore_MissingSourceData_KeepsFinding(t *testing.T) {
	findings := []finding.Finding{
		{
			DetectorID: "aws-access-key-id",
			SourceMetadata: finding.SourceMetadata{
				FilePath: "unknown.py",
				Line:     1,
			},
		},
	}

	result := FilterFindingsByInlineIgnore(findings, map[string][]byte{})

	if len(result) != 1 {
		t.Fatalf("expected 1 finding when source data missing, got %d", len(result))
	}
}

func TestLineHasInlineIgnore(t *testing.T) {
	data := []byte("line1 safe\n" + // line 1
		`API_KEY = "AKIAEXAMPLE" # leakwatch:ignore` + "\n" + // line 2 generic
		`TOKEN = "ghp_x" # leakwatch:ignore:github-token` + "\n" + // line 3 specific
		"line4 safe\n") // line 4

	tests := []struct {
		name       string
		lineNum    int
		detectorID string
		want       bool
	}{
		{"generic marker matches any detector", 2, "aws-access-key-id", true},
		{"specific marker matches its detector", 3, "github-token", true},
		{"specific marker ignores other detectors", 3, "aws-access-key-id", false},
		{"clean line is not ignored", 1, "aws-access-key-id", false},
		{"line zero is never ignored", 0, "aws-access-key-id", false},
		{"negative line is never ignored", -5, "aws-access-key-id", false},
		{"out-of-range line is not ignored", 999, "aws-access-key-id", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := LineHasInlineIgnore(data, tt.lineNum, tt.detectorID)
			if got != tt.want {
				t.Errorf("LineHasInlineIgnore(line=%d, %q) = %v, want %v", tt.lineNum, tt.detectorID, got, tt.want)
			}
		})
	}
}
