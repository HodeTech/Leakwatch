package detector

// redactMask is the fixed mask placed in front of the revealed suffix.
const redactMask = "****"

// revealedSuffixLen is the maximum number of trailing characters that Redact
// leaves visible. It is intentionally small so that a redacted value carries
// just enough information to correlate findings without exposing usable secret
// material.
const revealedSuffixLen = 4

// Redact returns a uniformly redacted representation of a secret value.
//
// The scheme is deliberately simple and consistent across every detector:
// reveal at most the last revealedSuffixLen characters of the value and never
// any leading body characters. The result is always "****" followed by the
// revealed suffix, e.g. Redact("AKIA1234567890ABCD") == "****ABCD".
//
// Detectors that match a value behind a FIXED literal prefix (for example a
// regex anchored on "sk-ant-") may prepend that constant prefix themselves;
// the prefix is part of the pattern, not secret-derived, so it leaks nothing.
// When in doubt prefer the bare "****"+suffix form.
//
// Redact never reveals the full value: if the value is shorter than or equal to
// revealedSuffixLen the entire value is masked.
func Redact(value string) string {
	if len(value) <= revealedSuffixLen {
		return redactMask
	}
	return redactMask + value[len(value)-revealedSuffixLen:]
}

// RedactBytes is the []byte convenience wrapper around Redact. It does not log,
// store, or otherwise retain the input beyond computing the redacted suffix.
func RedactBytes(value []byte) string {
	if len(value) <= revealedSuffixLen {
		return redactMask
	}
	return redactMask + string(value[len(value)-revealedSuffixLen:])
}
