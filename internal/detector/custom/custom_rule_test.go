package custom

import (
	"context"
	"strings"
	"testing"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewFromDef_ValidRule_ReturnsDetector(t *testing.T) {
	def := RuleDef{
		ID:          "internal-api-key",
		Description: "Internal API Key",
		Regex:       `INTERNAL_[A-Z0-9]{32}`,
		Keywords:    []string{"INTERNAL_"},
		Severity:    "high",
	}

	det, err := NewFromDef(def)
	require.NoError(t, err)
	assert.Equal(t, "internal-api-key", det.ID())
	assert.Equal(t, "Internal API Key", det.Description())
	assert.Equal(t, finding.SeverityHigh, det.Severity())
	assert.Equal(t, []string{"INTERNAL_"}, det.Keywords())
}

func TestNewFromDef_EmptyID_ReturnsError(t *testing.T) {
	def := RuleDef{Regex: `test`}
	_, err := NewFromDef(def)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ID is required")
}

func TestNewFromDef_EmptyRegex_ReturnsError(t *testing.T) {
	def := RuleDef{ID: "test"}
	_, err := NewFromDef(def)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "regex is required")
}

func TestNewFromDef_InvalidRegex_ReturnsError(t *testing.T) {
	def := RuleDef{ID: "test", Regex: `[unclosed`}
	_, err := NewFromDef(def)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid regex")
}

func TestNewFromDef_RegexTooLong_ReturnsError(t *testing.T) {
	longRegex := strings.Repeat("a", maxRegexLength+1)
	def := RuleDef{ID: "test", Regex: longRegex}
	_, err := NewFromDef(def)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds maximum")
}

func TestCustomDetector_Scan_MatchFound_ReturnsFinding(t *testing.T) {
	def := RuleDef{
		ID:    "test-pattern",
		Regex: `TOKEN_[A-Z0-9]{16}`,
	}
	det, err := NewFromDef(def)
	require.NoError(t, err)

	findings := det.Scan(context.Background(), []byte("found TOKEN_ABCDEF1234567890 here"))
	require.Len(t, findings, 1)
	assert.Equal(t, "test-pattern", findings[0].DetectorID)
	assert.Equal(t, "****7890", findings[0].Redacted)
}

func TestCustomDetector_Scan_NoMatch_ReturnsNil(t *testing.T) {
	def := RuleDef{
		ID:    "test-pattern",
		Regex: `TOKEN_[A-Z0-9]{16}`,
	}
	det, err := NewFromDef(def)
	require.NoError(t, err)

	findings := det.Scan(context.Background(), []byte("no secrets here"))
	assert.Nil(t, findings)
}

func TestCustomDetector_Scan_LowEntropy_SkipsMatch(t *testing.T) {
	def := RuleDef{
		ID:      "test-entropy",
		Regex:   `KEY_[A-Za-z0-9]{16}`,
		Entropy: 3.5,
	}
	det, err := NewFromDef(def)
	require.NoError(t, err)

	// Low entropy: repeating characters
	findings := det.Scan(context.Background(), []byte("KEY_AAAAAAAAAAAAAAAA"))
	assert.Empty(t, findings, "low entropy match should be skipped")
}

func TestCustomDetector_Scan_HighEntropy_ReturnsFinding(t *testing.T) {
	def := RuleDef{
		ID:      "test-entropy",
		Regex:   `KEY_[A-Za-z0-9]{16}`,
		Entropy: 2.0,
	}
	det, err := NewFromDef(def)
	require.NoError(t, err)

	findings := det.Scan(context.Background(), []byte("KEY_aB3kL9mN2pQ7rT4x"))
	assert.Len(t, findings, 1)
}

func TestCustomDetector_Severity_DefaultsMedium(t *testing.T) {
	def := RuleDef{ID: "test", Regex: `test`}
	det, err := NewFromDef(def)
	require.NoError(t, err)
	assert.Equal(t, finding.SeverityMedium, det.Severity())
}

func TestRegisterCustomRules_ValidRules_RegistersAll(t *testing.T) {
	detector.Reset()
	defer detector.Reset()

	rules := []RuleDef{
		{ID: "custom-1", Regex: `CUSTOM1_[A-Z]{10}`, Keywords: []string{"CUSTOM1_"}},
		{ID: "custom-2", Regex: `CUSTOM2_[A-Z]{10}`, Keywords: []string{"CUSTOM2_"}},
	}

	count, errs := RegisterCustomRules(rules)
	assert.Equal(t, 2, count)
	assert.Empty(t, errs)

	all := detector.All()
	assert.Len(t, all, 2)
}

func TestRegisterCustomRules_MixedValidity_RegistersValidOnly(t *testing.T) {
	detector.Reset()
	defer detector.Reset()

	rules := []RuleDef{
		{ID: "valid", Regex: `VALID_[A-Z]{10}`},
		{ID: "invalid", Regex: `[unclosed`},
	}

	count, errs := RegisterCustomRules(rules)
	assert.Equal(t, 1, count)
	assert.Len(t, errs, 1)
}

func TestRegisterCustomRules_DuplicateID_SkipsWithoutPanic(t *testing.T) {
	detector.Reset()
	defer detector.Reset()

	// A custom rule whose ID collides with an already-registered detector must
	// be skipped with an error — never registered, because detector.Register
	// panics on duplicate IDs.
	first := []RuleDef{{ID: "dupe", Regex: `DUPE_[A-Z]{10}`}}
	count, errs := RegisterCustomRules(first)
	require.Equal(t, 1, count)
	require.Empty(t, errs)

	assert.NotPanics(t, func() {
		second := []RuleDef{{ID: "dupe", Regex: `OTHER_[A-Z]{10}`}}
		count, errs = RegisterCustomRules(second)
	})
	assert.Equal(t, 0, count)
	require.Len(t, errs, 1)
	assert.Contains(t, errs[0].Error(), "already registered")

	// Only the original detector remains registered.
	assert.Len(t, detector.All(), 1)
}
