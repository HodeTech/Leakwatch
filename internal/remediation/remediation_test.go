package remediation

import (
	"testing"

	"github.com/HodeTech/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegister_SingleDetector_RetrievesCorrectly(t *testing.T) {
	t.Cleanup(func() { Reset() })
	Reset()

	r := finding.Remediation{
		Title:   "Rotate Test Key",
		Steps:   []string{"Step 1", "Step 2"},
		Urgency: "high",
	}
	Register("test-detector", r)

	got := Get("test-detector")
	require.NotNil(t, got)
	assert.Equal(t, "Rotate Test Key", got.Title)
	assert.Equal(t, []string{"Step 1", "Step 2"}, got.Steps)
	assert.Equal(t, "high", got.Urgency)
}

func TestGet_UnregisteredDetector_ReturnsNil(t *testing.T) {
	t.Cleanup(func() { Reset() })
	Reset()

	got := Get("nonexistent-detector")
	assert.Nil(t, got)
}

func TestEnrichFindings_MatchingDetector_AttachesRemediation(t *testing.T) {
	t.Cleanup(func() { Reset() })
	Reset()

	r := finding.Remediation{
		Title:   "Fix It",
		Steps:   []string{"Do the thing"},
		Urgency: "immediate",
	}
	Register("my-detector", r)

	findings := []finding.Finding{
		{DetectorID: "my-detector", Redacted: "REDACTED"},
	}

	enriched := EnrichFindings(findings)
	require.Len(t, enriched, 1)
	require.NotNil(t, enriched[0].Remediation)
	assert.Equal(t, "Fix It", enriched[0].Remediation.Title)
	assert.Equal(t, "immediate", enriched[0].Remediation.Urgency)
}

func TestEnrichFindings_NoMatch_LeavesNil(t *testing.T) {
	t.Cleanup(func() { Reset() })
	Reset()

	findings := []finding.Finding{
		{DetectorID: "unknown-detector", Redacted: "REDACTED"},
	}

	enriched := EnrichFindings(findings)
	require.Len(t, enriched, 1)
	assert.Nil(t, enriched[0].Remediation)
}

func TestEnrichFindings_DoesNotMutateInput(t *testing.T) {
	t.Cleanup(func() { Reset() })
	Reset()

	r := finding.Remediation{
		Title:   "Rotate Key",
		Steps:   []string{"Step 1"},
		Urgency: "high",
	}
	Register("det-a", r)

	original := []finding.Finding{
		{DetectorID: "det-a", Redacted: "REDACTED"},
	}

	enriched := EnrichFindings(original)

	// The original slice must remain unmodified.
	assert.Nil(t, original[0].Remediation, "input slice must not be mutated")
	require.NotNil(t, enriched[0].Remediation)
	assert.Equal(t, "Rotate Key", enriched[0].Remediation.Title)
}

func TestRegister_DuplicateID_Overwrites(t *testing.T) {
	t.Cleanup(func() { Reset() })
	Reset()

	first := finding.Remediation{Title: "First", Urgency: "medium"}
	second := finding.Remediation{Title: "Second", Urgency: "high"}

	Register("dup-detector", first)
	Register("dup-detector", second)

	got := Get("dup-detector")
	require.NotNil(t, got)
	assert.Equal(t, "Second", got.Title, "duplicate registration should overwrite the previous entry")
	assert.Equal(t, "high", got.Urgency)
}

func TestReset_ClearsRegistry(t *testing.T) {
	Reset()

	Register("temp-detector", finding.Remediation{Title: "Temp", Urgency: "low"})
	require.NotNil(t, Get("temp-detector"))

	Reset()
	assert.Nil(t, Get("temp-detector"), "registry should be empty after Reset")
}
