package ftp

import (
	"context"
	"testing"

	"github.com/HodeTech/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetector_Metadata_ReturnsExpectedValues(t *testing.T) {
	d := &Detector{}
	assert.Equal(t, "ftp-credentials", d.ID())
	assert.Equal(t, "FTP/SFTP Credentials", d.Description())
	assert.Equal(t, finding.SeverityCritical, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestDetector_Scan_MatchesValidStrings(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "ftp with user and password",
			input:    "ftp://deploy:s3cretP4ss@ftp.example.com:21/uploads",
			expected: 1,
			redacted: "ftp://deploy:****@ftp.example.com:21/uploads",
		},
		{
			name:     "sftp connection",
			input:    "sftp://admin:P@ssw0rd@sftp.example.com:22/data",
			expected: 1,
			redacted: "sftp://admin:****@sftp.example.com:22/data",
		},
		{
			name:     "ftps TLS connection",
			input:    "ftps://user:tlspass@ftps.example.com:990/secure",
			expected: 1,
			redacted: "ftps://user:****@ftps.example.com:990/secure",
		},
		{
			name:     "ftp in env var",
			input:    `FTP_URL=ftp://uploader:testpass@localhost:21/pub`,
			expected: 1,
			redacted: "ftp://uploader:****@localhost:21/pub",
		},
		{
			name:     "ftp in JSON config",
			input:    `{"ftp_url": "ftp://app:dbpass123@ftp-host:21/files"}`,
			expected: 1,
			redacted: "ftp://app:****@ftp-host:21/files",
		},
		{
			name:     "multiple ftp URLs",
			input:    "ftp://a:pass1@host1:21/dir sftp://b:pass2@host2:22/dir",
			expected: 2,
		},
	}

	d := &Detector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Scan(context.Background(), []byte(tt.input))
			assert.Len(t, findings, tt.expected)
			if tt.expected > 0 && tt.redacted != "" {
				require.NotEmpty(t, findings)
				assert.Equal(t, tt.redacted, findings[0].Redacted)
			}
		})
	}
}

func TestDetector_Scan_RejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "ftp URL without credentials",
			input: "ftp://ftp.example.com/pub",
		},
		{
			name:  "http URL not ftp",
			input: "http://example.com/api/v1",
		},
		{
			name:  "plain text",
			input: "this is just normal text",
		},
		{
			name:  "empty input",
			input: "",
		},
	}

	d := &Detector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := d.Scan(context.Background(), []byte(tt.input))
			assert.Empty(t, findings)
		})
	}
}

func TestRedactPassword_VariousFormats(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "standard ftp user:pass@host",
			input:    "ftp://user:password@host:21/path",
			expected: "ftp://user:****@host:21/path",
		},
		{
			name:     "no credentials in URL",
			input:    "ftp://host:21/path",
			expected: "ftp://host:21/path",
		},
		{
			name:     "user without password",
			input:    "ftp://user@host:21/path",
			expected: "ftp://user:****@host:21/path",
		},
		{
			name:     "sftp scheme",
			input:    "sftp://admin:secret@host:22/data",
			expected: "sftp://admin:****@host:22/data",
		},
		{
			name:     "ftps scheme",
			input:    "ftps://admin:secret@host:990/data",
			expected: "ftps://admin:****@host:990/data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := redactPassword(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
