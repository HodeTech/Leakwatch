// Package privatekey provides private key detectors.
package privatekey

import (
	"context"
	"regexp"
	"strconv"

	"github.com/cemililik/leakwatch/internal/detector"
	"github.com/cemililik/leakwatch/pkg/finding"
)

var (
	privateKeyPattern = regexp.MustCompile(`-----BEGIN\s+(RSA |OPENSSH |DSA |EC |PGP )?PRIVATE KEY( BLOCK)?-----`)
	// privateKeyEndPattern locates the closing armor so the full PEM block
	// region can be measured without retaining the key body between them.
	privateKeyEndPattern = regexp.MustCompile(`-----END\s+(?:RSA |OPENSSH |DSA |EC |PGP )?PRIVATE KEY(?: BLOCK)?-----`)
)

// Detector detects PEM-encoded private keys.
type Detector struct{}

func (d *Detector) ID() string { return "private-key" }

func (d *Detector) Description() string { return "Private Key (RSA, SSH, DSA, EC, PGP)" }
func (d *Detector) Keywords() []string {
	return []string{
		"-----BEGIN RSA PRIVATE",
		"-----BEGIN OPENSSH PRIVATE",
		"-----BEGIN DSA PRIVATE",
		"-----BEGIN EC PRIVATE",
		"-----BEGIN PGP PRIVATE",
		"-----BEGIN PRIVATE KEY",
	}
}
func (d *Detector) Severity() finding.Severity { return finding.SeverityCritical }

// Scan searches the data for PEM private key blocks. It locates the BEGIN/END
// armor pair so the full block REGION is captured for span/dedup purposes, but
// it never stores the key body: Raw holds only the BEGIN header and the byte
// span of the block is reported via ExtraData. The PEM body between the armor
// lines is deliberately discarded.
func (d *Detector) Scan(_ context.Context, data []byte) []detector.RawFinding {
	locs := privateKeyPattern.FindAllIndex(data, -1)
	if len(locs) == 0 {
		return nil
	}

	findings := make([]detector.RawFinding, 0, len(locs))
	for _, loc := range locs {
		header := data[loc[0]:loc[1]]

		// Determine the block region by finding the next END armor after the
		// header. We only record its length, never the bytes in between.
		blockLen := loc[1] - loc[0]
		if end := privateKeyEndPattern.FindIndex(data[loc[1]:]); end != nil {
			blockLen = (loc[1] + end[1]) - loc[0]
		}

		findings = append(findings, detector.RawFinding{
			DetectorID: d.ID(),
			// Raw is the header only; the key body is never retained.
			Raw:      header,
			Redacted: "-----BEGIN [REDACTED] PRIVATE KEY-----",
			ExtraData: map[string]string{
				"block_bytes": strconv.Itoa(blockLen),
			},
		})
	}
	return findings
}

func init() {
	detector.Register(&Detector{})
}
