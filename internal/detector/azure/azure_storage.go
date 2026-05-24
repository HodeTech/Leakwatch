// Package azure provides Azure secret detectors.
package azure

import (
	"context"
	"regexp"

	"github.com/HodeTech/leakwatch/internal/detector"
	"github.com/HodeTech/leakwatch/pkg/finding"
)

var (
	azureStoragePattern     = regexp.MustCompile(`DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{86,88};`)
	azureAccountNamePattern = regexp.MustCompile(`AccountName=([^;]+)`)
)

// StorageDetector detects Azure Storage Connection Strings.
type StorageDetector struct{}

// ID returns the unique identifier of the Azure Storage detector.
func (d *StorageDetector) ID() string { return "azure-storage-key" }

// Description returns a human-readable description of the Azure Storage detector.
func (d *StorageDetector) Description() string { return "Azure Storage Connection String" }

// Keywords returns the Aho-Corasick pre-filter keywords for Azure Storage detection.
func (d *StorageDetector) Keywords() []string {
	return []string{"DefaultEndpointsProtocol", "AccountKey"}
}

// Severity returns the default severity level for Azure Storage findings.
func (d *StorageDetector) Severity() finding.Severity { return finding.SeverityCritical }

// Scan searches the data for Azure Storage Connection String patterns.
func (d *StorageDetector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	matches := azureStoragePattern.FindAll(data, -1)
	if len(matches) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(matches))
	for _, match := range matches {
		accountName := extractAccountName(match)
		redacted := "AccountName=" + accountName + ";AccountKey=****"

		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			Raw:        match,
			Redacted:   redacted,
			ExtraData: map[string]string{
				"account_name": accountName,
			},
		})
	}
	return findings
}

// extractAccountName extracts the AccountName value from the connection string.
func extractAccountName(data []byte) string {
	groups := azureAccountNamePattern.FindSubmatch(data)
	if len(groups) < 2 {
		return "unknown"
	}
	return string(groups[1])
}

func init() {
	detector.Register(&StorageDetector{})
}
