package privatekey

import (
	"context"
	"testing"

	"github.com/HodeTech/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
)

func TestDetector_Metadata(t *testing.T) {
	d := &Detector{}
	assert.Equal(t, "private-key", d.ID())
	assert.Equal(t, finding.SeverityCritical, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestDetector_Scan(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{
			name:     "RSA private key",
			input:    "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----",
			expected: 1,
		},
		{
			name:     "OpenSSH private key",
			input:    "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blb...\n-----END OPENSSH PRIVATE KEY-----",
			expected: 1,
		},
		{
			name:     "EC private key",
			input:    "-----BEGIN EC PRIVATE KEY-----\nMHQC...\n-----END EC PRIVATE KEY-----",
			expected: 1,
		},
		{
			name:     "DSA private key",
			input:    "-----BEGIN DSA PRIVATE KEY-----\nMIIB...\n-----END DSA PRIVATE KEY-----",
			expected: 1,
		},
		{
			name:     "generic private key (PKCS8)",
			input:    "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----",
			expected: 1,
		},
		{
			name:     "PGP private key block",
			input:    "-----BEGIN PGP PRIVATE KEY BLOCK-----\nxcLY...",
			expected: 1,
		},
		{
			name:     "public key - no match",
			input:    "-----BEGIN PUBLIC KEY-----\nMIIB...\n-----END PUBLIC KEY-----",
			expected: 0,
		},
		{
			name:     "certificate - no match",
			input:    "-----BEGIN CERTIFICATE-----\nMIIE...\n-----END CERTIFICATE-----",
			expected: 0,
		},
		{
			name:     "plain text - no match",
			input:    "just some normal text",
			expected: 0,
		},
		{
			name:     "empty input",
			input:    "",
			expected: 0,
		},
		{
			name:     "multiple keys",
			input:    "-----BEGIN RSA PRIVATE KEY-----\n...\n-----BEGIN EC PRIVATE KEY-----",
			expected: 2,
		},
	}

	d := &Detector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Scan(context.Background(), []byte(tt.input))
			assert.Len(t, findings, tt.expected)
		})
	}
}

// TestDetector_Scan_CapturesBlockRegionWithoutLeakingBody verifies DETB-M-02:
// the detector measures the full BEGIN..END block region but never stores the
// key body in Raw, RawV2, or Redacted. The body below is clearly fake.
func TestDetector_Scan_CapturesBlockRegionWithoutLeakingBody(t *testing.T) {
	body := "FAKEBODYLINE1FAKEBODYLINE2FAKEBODYLINE3"
	pem := "-----BEGIN RSA PRIVATE KEY-----\n" + body + "\n-----END RSA PRIVATE KEY-----"

	d := &Detector{}
	findings := d.Scan(context.Background(), []byte(pem))

	assert.Len(t, findings, 1)
	f := findings[0]

	// The PEM body must never appear in any stored field.
	assert.NotContains(t, string(f.Raw), "FAKEBODY")
	assert.NotContains(t, string(f.RawV2), "FAKEBODY")
	assert.NotContains(t, f.Redacted, "FAKEBODY")

	// The block region length must span the whole BEGIN..END block.
	assert.Equal(t, "block_bytes", firstKey(f.ExtraData))
	assert.Equal(t, len(pem), blockBytes(t, f.ExtraData))
}

func firstKey(m map[string]string) string {
	for k := range m {
		return k
	}
	return ""
}

func blockBytes(t *testing.T, m map[string]string) int {
	t.Helper()
	v, ok := m["block_bytes"]
	assert.True(t, ok, "block_bytes must be present")
	n := 0
	for _, c := range v {
		n = n*10 + int(c-'0')
	}
	return n
}
