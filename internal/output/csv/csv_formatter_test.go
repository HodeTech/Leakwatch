package csv

import (
	"bytes"
	"encoding/csv"
	"errors"
	"testing"
	"time"

	"github.com/cemililik/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFormatter_Format_EmptyFindings_WritesHeaderOnly(t *testing.T) {
	f := &Formatter{}
	var buf bytes.Buffer

	err := f.Format(&buf, []finding.Finding{})
	require.NoError(t, err)

	reader := csv.NewReader(&buf)
	records, err := reader.ReadAll()
	require.NoError(t, err)

	require.Len(t, records, 1, "should only contain the header row")
	assert.Equal(t, []string{"id", "detector_id", "severity", "redacted", "file_path", "commit", "verification_status", "remediation"}, records[0])
}

func TestFormatter_Format_SingleFinding_WritesCorrectRow(t *testing.T) {
	f := &Formatter{}
	var buf bytes.Buffer

	findings := []finding.Finding{
		{
			ID:         "abc123",
			DetectorID: "aws-access-key-id",
			Severity:   finding.SeverityCritical,
			Redacted:   "AKIA****MPLE",
			SourceMetadata: finding.SourceMetadata{
				FilePath: "config.yaml",
				Commit:   "deadbeef",
			},
			Verification: finding.VerificationResult{
				Status: finding.StatusVerifiedActive,
			},
			DetectedAt: time.Now(),
		},
	}

	err := f.Format(&buf, findings)
	require.NoError(t, err)

	reader := csv.NewReader(bytes.NewReader(buf.Bytes()))
	records, err := reader.ReadAll()
	require.NoError(t, err)

	require.Len(t, records, 2, "header + 1 data row")
	row := records[1]
	assert.Equal(t, "abc123", row[0])
	assert.Equal(t, "aws-access-key-id", row[1])
	assert.Equal(t, "critical", row[2])
	assert.Equal(t, "AKIA****MPLE", row[3])
	assert.Equal(t, "config.yaml", row[4])
	assert.Equal(t, "deadbeef", row[5])
	assert.Equal(t, "verified_active", row[6])
}

func TestFormatter_Format_ShowRawFalse_StripsRawFromOutput(t *testing.T) {
	f := &Formatter{ShowRaw: false}
	var buf bytes.Buffer

	findings := []finding.Finding{
		{
			ID:         "test-1",
			DetectorID: "generic-secret",
			Redacted:   "sk_****abcd",
			Raw:        "sk_live_supersecretvalue",
		},
	}

	err := f.Format(&buf, findings)
	require.NoError(t, err)

	assert.NotContains(t, buf.String(), "sk_live_supersecretvalue",
		"ShowRaw=false must strip raw secret from CSV output")
}

func TestFormatter_Format_ShowRawFalse_DoesNotMutateOriginal(t *testing.T) {
	f := &Formatter{ShowRaw: false}
	var buf bytes.Buffer

	findings := []finding.Finding{
		{
			ID:  "test-1",
			Raw: "AKIAIOSFODNN7EXAMPLE",
		},
	}

	err := f.Format(&buf, findings)
	require.NoError(t, err)

	assert.Equal(t, "AKIAIOSFODNN7EXAMPLE", findings[0].Raw,
		"Format must not mutate the original slice")
}

func TestFormatter_Format_SpecialCharacters_ProperlyEscaped(t *testing.T) {
	f := &Formatter{}
	var buf bytes.Buffer

	findings := []finding.Finding{
		{
			ID:         "esc-test",
			DetectorID: "generic",
			Redacted:   "value,with\"quotes\nand,commas",
			SourceMetadata: finding.SourceMetadata{
				FilePath: "path/with spaces/file.go",
			},
		},
	}

	err := f.Format(&buf, findings)
	require.NoError(t, err)

	reader := csv.NewReader(bytes.NewReader(buf.Bytes()))
	records, err := reader.ReadAll()
	require.NoError(t, err)

	require.Len(t, records, 2)
	assert.Equal(t, "value,with\"quotes\nand,commas", records[1][3])
	assert.Equal(t, "path/with spaces/file.go", records[1][4])
}

func TestFormatter_Format_WithRemediation_CSVHasRemediationColumn(t *testing.T) {
	f := &Formatter{}
	var buf bytes.Buffer

	findings := []finding.Finding{
		{
			ID:         "rem-1",
			DetectorID: "aws-access-key-id",
			Severity:   finding.SeverityCritical,
			Redacted:   "AKIA****MPLE",
			SourceMetadata: finding.SourceMetadata{
				FilePath: "config.yaml",
				Commit:   "deadbeef",
			},
			Verification: finding.VerificationResult{
				Status: finding.StatusVerifiedActive,
			},
			Remediation: &finding.Remediation{
				Title:   "Rotate AWS Access Key",
				Steps:   []string{"Deactivate the key", "Create a new key"},
				DocURL:  "https://docs.aws.amazon.com/iam",
				Urgency: "immediate",
			},
			DetectedAt: time.Now(),
		},
	}

	err := f.Format(&buf, findings)
	require.NoError(t, err)

	reader := csv.NewReader(bytes.NewReader(buf.Bytes()))
	records, err := reader.ReadAll()
	require.NoError(t, err)

	require.Len(t, records, 2)
	assert.Equal(t, "remediation", records[0][7])
	assert.Equal(t, "Rotate AWS Access Key", records[1][7])
}

func TestFormatter_Format_WithoutRemediation_CSVHasEmptyRemediationColumn(t *testing.T) {
	f := &Formatter{}
	var buf bytes.Buffer

	findings := []finding.Finding{
		{
			ID:         "no-rem-1",
			DetectorID: "generic-secret",
			Severity:   finding.SeverityMedium,
			Redacted:   "****",
		},
	}

	err := f.Format(&buf, findings)
	require.NoError(t, err)

	reader := csv.NewReader(bytes.NewReader(buf.Bytes()))
	records, err := reader.ReadAll()
	require.NoError(t, err)

	require.Len(t, records, 2)
	assert.Equal(t, "remediation", records[0][7])
	assert.Equal(t, "", records[1][7])
}

func TestFormatter_Format_ShowRawFalse_NoRawColumn(t *testing.T) {
	f := &Formatter{ShowRaw: false}
	var buf bytes.Buffer

	findings := []finding.Finding{
		{
			ID:       "test-1",
			Redacted: "sk_****abcd",
			Raw:      "sk_live_supersecretvalue",
		},
	}

	err := f.Format(&buf, findings)
	require.NoError(t, err)

	reader := csv.NewReader(bytes.NewReader(buf.Bytes()))
	records, err := reader.ReadAll()
	require.NoError(t, err)

	require.Len(t, records, 2)
	assert.Len(t, records[0], 8, "header must not include a raw column when ShowRaw=false")
	assert.NotContains(t, records[0], "raw")
}

func TestFormatter_Format_ShowRawTrue_AddsRawColumn(t *testing.T) {
	f := &Formatter{ShowRaw: true}
	var buf bytes.Buffer

	findings := []finding.Finding{
		{
			ID:       "test-1",
			Redacted: "sk_****abcd",
			Raw:      "sk_live_supersecretvalue",
		},
	}

	err := f.Format(&buf, findings)
	require.NoError(t, err)

	reader := csv.NewReader(bytes.NewReader(buf.Bytes()))
	records, err := reader.ReadAll()
	require.NoError(t, err)

	require.Len(t, records, 2)
	require.Len(t, records[0], 9, "header must include a trailing raw column when ShowRaw=true")
	assert.Equal(t, "raw", records[0][8])
	assert.Equal(t, "sk_live_supersecretvalue", records[1][8])
}

func TestFormatter_Format_FormulaInjection_CellsArePrefixed(t *testing.T) {
	f := &Formatter{ShowRaw: true}
	var buf bytes.Buffer

	findings := []finding.Finding{
		{
			ID:         "=cmd|' /c calc'!A1",
			DetectorID: "+SUM(1,2)",
			Redacted:   "-2+3",
			Raw:        "@evil",
			SourceMetadata: finding.SourceMetadata{
				FilePath: "\tleading-tab",
			},
			Remediation: &finding.Remediation{
				Title: "\rcarriage",
			},
		},
	}

	err := f.Format(&buf, findings)
	require.NoError(t, err)

	reader := csv.NewReader(bytes.NewReader(buf.Bytes()))
	records, err := reader.ReadAll()
	require.NoError(t, err)

	require.Len(t, records, 2)
	row := records[1]
	assert.Equal(t, "'=cmd|' /c calc'!A1", row[0], "= cell must be quote-prefixed")
	assert.Equal(t, "'+SUM(1,2)", row[1], "+ cell must be quote-prefixed")
	assert.Equal(t, "'-2+3", row[3], "- cell must be quote-prefixed")
	assert.Equal(t, "'\tleading-tab", row[4], "tab-leading cell must be quote-prefixed")
	assert.Equal(t, "'\rcarriage", row[7], "CR-leading cell must be quote-prefixed")
	assert.Equal(t, "'@evil", row[8], "@ cell must be quote-prefixed")
}

func TestFormatter_Format_FormulaInjection_SafeCellsUntouched(t *testing.T) {
	f := &Formatter{}
	var buf bytes.Buffer

	findings := []finding.Finding{
		{
			ID:         "safe-id",
			DetectorID: "aws-access-key-id",
			Redacted:   "AKIA****MPLE",
		},
	}

	err := f.Format(&buf, findings)
	require.NoError(t, err)

	reader := csv.NewReader(bytes.NewReader(buf.Bytes()))
	records, err := reader.ReadAll()
	require.NoError(t, err)

	require.Len(t, records, 2)
	assert.Equal(t, "safe-id", records[1][0])
	assert.Equal(t, "aws-access-key-id", records[1][1])
	assert.Equal(t, "AKIA****MPLE", records[1][3])
}

func TestFormatter_FileExtension_ReturnsCSV(t *testing.T) {
	f := &Formatter{}
	assert.Equal(t, ".csv", f.FileExtension())
}

// errWriter simulates a write error.
type errWriter struct{}

func (w *errWriter) Write(_ []byte) (int, error) {
	return 0, errors.New("write error")
}

func TestFormatter_Format_WriterError_ReturnsError(t *testing.T) {
	f := &Formatter{}
	findings := []finding.Finding{{ID: "test"}}

	err := f.Format(&errWriter{}, findings)
	assert.Error(t, err)
}
