package telegram

import (
	"strings"
	"testing"

	"github.com/cemililik/leakwatch/internal/detector/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDetector_ScanViaMatcher_StandaloneToken_IsDetected is a regression test
// for the keyword/regex misalignment (DETB-M-01). A standalone Telegram token
// carries none of the words "telegram"/"bot_token", so it must not be gated out
// by the Aho-Corasick matcher before Scan runs.
func TestDetector_ScanViaMatcher_StandaloneToken_IsDetected(t *testing.T) {
	suffix35 := strings.Repeat("Ab1Cd", 7)
	token := "123456789:" + suffix35

	d := &Detector{}
	findings := testutil.ScanViaMatcher(d, []byte(token))

	require.Len(t, findings, 1, "standalone token must survive the matcher gate")
	assert.Equal(t, "telegram-bot-token", findings[0].DetectorID)
	assert.Equal(t, "****"+suffix35[len(suffix35)-4:], findings[0].Redacted)
}
