package dbconn

import (
	"context"
	"strings"
	"testing"

	"github.com/cemililik/leakwatch/pkg/finding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConnectionString_Metadata(t *testing.T) {
	d := &ConnectionString{}
	assert.Equal(t, "database-connection-string", d.ID())
	assert.Equal(t, "Database Connection String", d.Description())
	assert.Equal(t, finding.SeverityCritical, d.Severity())
	assert.NotEmpty(t, d.Keywords())
}

func TestConnectionString_Scan_MatchesValidStrings(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
		redacted string
	}{
		{
			name:     "postgres connection string",
			input:    "postgres://admin:secretpass@localhost:5432/mydb",
			expected: 1,
			redacted: "postgres://admin:****@localhost:5432/mydb",
		},
		{
			name:     "mysql connection string",
			input:    "mysql://root:p4ssw0rd@db.example.com:3306/app",
			expected: 1,
			redacted: "mysql://root:****@db.example.com:3306/app",
		},
		{
			name:     "mongodb connection string",
			input:    "mongodb://user:pass1234@mongo.example.com:27017/test",
			expected: 1,
			redacted: "mongodb://user:****@mongo.example.com:27017/test",
		},
		{
			name:     "mongodb+srv connection string",
			input:    "mongodb+srv://user:pass1234@cluster0.example.net/mydb",
			expected: 1,
			redacted: "mongodb+srv://user:****@cluster0.example.net/mydb",
		},
		{
			name:     "redis connection string",
			input:    "redis://default:redispass@cache.example.com:6379/0",
			expected: 1,
			redacted: "redis://default:****@cache.example.com:6379/0",
		},
		{
			name:     "connection string in env var",
			input:    `DATABASE_URL=postgres://admin:secretpass@localhost:5432/mydb`,
			expected: 1,
		},
		{
			name:     "connection string in JSON",
			input:    `{"dsn": "mysql://root:p4ssw0rd@db.example.com:3306/app"}`,
			expected: 1,
		},
		{
			name:     "multiple connection strings",
			input:    "postgres://admin:secretpass@localhost:5432/mydb mysql://root:p4ssw0rd@db.example.com:3306/app",
			expected: 2,
		},
		{
			name:     "connection string in large text",
			input:    strings.Repeat("x", 10000) + "postgres://admin:secretpass@localhost:5432/mydb" + strings.Repeat("y", 10000),
			expected: 1,
		},
	}

	d := &ConnectionString{}
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

func TestConnectionString_Scan_RejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "http URL not a database",
			input: "http://example.com/api/v1",
		},
		{
			name:  "too short after scheme",
			input: "postgres://short",
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

	d := &ConnectionString{}
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
			name:     "standard user:pass@host",
			input:    "postgres://user:password@host:5432/db",
			expected: "postgres://user:****@host:5432/db",
		},
		{
			name:     "no password in URL",
			input:    "postgres://host:5432/db",
			expected: "postgres://****",
		},
		{
			name:     "user without password",
			input:    "postgres://user@host:5432/db",
			expected: "postgres://user****",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := redactPassword(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
