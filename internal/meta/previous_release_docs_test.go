package meta

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// changelogReleaseHeading matches a released section heading such as
// "## [v1.8.3] - 2026-11-12". "## [Unreleased]" and the "###" subsections do
// not match. It is applied line by line, outside fenced code blocks.
var changelogReleaseHeading = regexp.MustCompile(`(?m)^##[[:space:]]+\[(` + releaseVersionTokenPattern + `)\]`)

// TestDocumentation_PreviousReleaseMentionsAreBumpedOrExplicitlyHistorical
// closes the gap the release-pin contract test leaves open.
//
// TestDocumentation_LeakwatchReleasePinsAreCurrentOrExplicitlyHistorical only
// recognizes pins in known contexts (an action input, a pre-commit rev, an
// image tag, ...). After a release the version that goes stale everywhere else
// is always the one that was current until now: an archive-name example, a
// "downloads the prebuilt vX binary" sentence, a `go install ...@vX` note, a
// bare "for example 1.8.2". This test finds every mention of the previous
// release in the current documentation, whatever its context, and requires it
// to be bumped or to sit in a block that declares it historical with the same
// <!-- leakwatch-version: historical vX.Y.Z --> marker the pin test uses.
func TestDocumentation_PreviousReleaseMentionsAreBumpedOrExplicitlyHistorical(t *testing.T) {
	root := filepath.Join("..", "..")
	changelog, err := os.ReadFile(filepath.Join(root, "CHANGELOG.md"))
	require.NoError(t, err)
	previous, err := previousReleaseVersion(string(changelog), ReleaseVersion)
	require.NoError(t, err)

	paths, err := currentDocumentationMarkdownPaths(root)
	require.NoError(t, err)
	require.NotEmpty(t, paths)

	for _, path := range paths {
		contents, readErr := os.ReadFile(path)
		require.NoError(t, readErr)
		for _, line := range stalePreviousReleaseLines(string(contents), previous) {
			t.Errorf("%s:%d mentions the previous release %s; bump it to %s if it is meant as current, or mark the same paragraph, table or fenced example with <!-- leakwatch-version: historical %s --> and explain why that exact version matters",
				filepath.ToSlash(path), line, previous, ReleaseVersion, previous)
		}
	}
}

func TestPreviousReleaseVersion_ChangelogHeadings_ReturnsReleaseBelowCurrentOrError(t *testing.T) {
	const changelog = "# Changelog\n\n## [Unreleased]\n\n## [v1.8.3] - 2026-11-12\n\n### Fixed\n\n- [v9.9.9] in a list item is not a heading\n\n## [v1.8.2] - 2026-11-12\n\n## [v1.8.1] - 2026-11-06\n"
	tests := []struct {
		name    string
		input   string
		current string
		want    string
		wantErr string
	}{
		{name: "release below the current one", input: changelog, current: "v1.8.3", want: "v1.8.2"},
		{name: "skips unreleased and subsections", input: changelog, current: "v1.8.2", want: "v1.8.1"},
		{name: "pre-release is the previous heading", input: "## [v1.9.0] - d\n\n## [v1.9.0-rc.1] - d\n", current: "v1.9.0", want: "v1.9.0-rc.1"},
		{name: "heading-shaped line in a fenced example is not a release", input: "## [v1.8.3] - d\n\n```md\n## [v9.9.9] - example\n```\n\n## [v1.8.2] - d\n", current: "v1.8.3", want: "v1.8.2"},
		{name: "current release is not in the changelog", input: changelog, current: "v1.8.4", wantErr: "no heading for v1.8.4"},
		{name: "current release is the oldest entry", input: changelog, current: "v1.8.1", wantErr: "no release below v1.8.1"},
		{name: "unreleased only", input: "## [Unreleased]\n", current: "v1.8.3", wantErr: "no heading for v1.8.3"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := previousReleaseVersion(tc.input, tc.current)
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestStalePreviousReleaseLines_MentionBoundariesAndMarkers_ReportsOnlyUnmarkedWholeVersionMentions(t *testing.T) {
	const version = "v1.8.2"
	tests := []struct {
		name     string
		contents string
		want     []int
	}{
		{name: "v-prefixed prose", contents: "This downloads the prebuilt `v1.8.2` binary.", want: []int{1}},
		{name: "bare version in output", contents: "intro\n\n```text\nleakwatch 1.8.2 (commit: abc1234, built: x)\n```", want: []int{4}},
		{name: "archive name with underscores", contents: "```text\nleakwatch_1.8.2_linux_amd64.tar.gz\n```", want: []int{2}},
		{name: "image tag with an architecture suffix", contents: "Verify `:1.8.2-amd64` instead.", want: []int{1}},
		{name: "release URL", contents: "See https://github.com/HodeTech/Leakwatch/releases/tag/v1.8.2 for details.", want: []int{1}},
		{name: "go install note", contents: "Replace `@latest` with `@v1.8.2`.", want: []int{1}},
		{name: "sentence end", contents: "It shipped in v1.8.2.", want: []int{1}},
		{name: "two mentions on one line count once", contents: "v1.8.2, 1.8.2 and `1.8.2`", want: []int{1}},
		{name: "mentions on separate lines", contents: "a\nv1.8.2\n\nb 1.8.2", want: []int{2, 4}},
		{name: "pre-release of the previous release is flagged too", contents: "Try v1.8.2-rc.1.", want: []int{1}},
		{name: "current release is fine", contents: "leakwatch 1.8.3 (commit: abc1234, built: x)"},
		{name: "longer patch number", contents: "v1.8.20 and 1.8.21"},
		{name: "longer dotted version", contents: "v1.8.2.1 and 1.8.2.10"},
		{name: "longer major number", contents: "v11.8.2"},
		{name: "address-like prefix", contents: "10.1.8.2"},
		{name: "glued to a word", contents: "dev1.8.2 and 1.8.2beta"},
		{name: "marker exempts its paragraph", contents: "<!-- leakwatch-version: historical v1.8.2 -->\n\nReleases up to v1.8.2 signed only per-arch images (`:1.8.2-amd64`)."},
		{name: "marker exempts a fenced example", contents: "<!-- leakwatch-version: historical v1.8.2 -->\n\n```text\nleakwatch_1.8.2_linux_amd64.tar.gz\n```"},
		{name: "marker covers a whole contiguous list", contents: "<!-- leakwatch-version: historical v1.8.2 -->\n\n- Up to v1.8.2.\n- Also v1.8.2."},
		{name: "blank line ends the marked list item", contents: "<!-- leakwatch-version: historical v1.8.2 -->\n\n- Up to v1.8.2.\n\n- Also v1.8.2.", want: []int{5}},
		{name: "marker does not exempt a later block", contents: "<!-- leakwatch-version: historical v1.8.2 -->\n\nUp to v1.8.2.\n\nUnrelated paragraph.\n\nSee v1.8.2.", want: []int{7}},
		{name: "marker for another version does not exempt", contents: "<!-- leakwatch-version: historical v1.8.1 -->\n\nUp to v1.8.2.", want: []int{3}},
		{name: "CRLF line endings", contents: "a\r\n\r\nv1.8.2\r\n", want: []int{3}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, stalePreviousReleaseLines(tc.contents, version))
		})
	}
}

// changelogReleaseVersions returns the released versions in the order their
// headings appear. A heading-shaped line inside a fenced code block is example
// text, not a release.
func changelogReleaseVersions(changelog string) []string {
	var versions []string
	inFence := false
	for _, line := range strings.Split(strings.ReplaceAll(changelog, "\r\n", "\n"), "\n") {
		if startsMarkdownFence(line) {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		if match := changelogReleaseHeading.FindStringSubmatch(line); match != nil {
			versions = append(versions, match[1])
		}
	}
	return versions
}

// previousReleaseVersion returns the release listed directly below current in
// the changelog, which is the version that was current until current shipped.
func previousReleaseVersion(changelog, current string) (string, error) {
	versions := changelogReleaseVersions(changelog)
	for index, version := range versions {
		if version != current {
			continue
		}
		if index+1 >= len(versions) {
			return "", fmt.Errorf("CHANGELOG.md has no release below %s to compare the documentation against", current)
		}
		return versions[index+1], nil
	}
	return "", fmt.Errorf("CHANGELOG.md has no heading for %s; cut its section before bumping ReleaseVersion", current)
}

// stalePreviousReleaseLines returns the ascending 1-based lines of contents
// that mention version, as "vX.Y.Z" or bare, outside a block that declares it
// historical.
func stalePreviousReleaseLines(contents, version string) []int {
	var lines []int
	for _, block := range markdownContractBlocks(contents) {
		if blockMarksHistoricalVersion(block.text, version) {
			continue
		}
		for _, offset := range releaseVersionMentionOffsets(block.text, version) {
			line := block.startLine + strings.Count(block.text[:offset], "\n")
			if len(lines) == 0 || lines[len(lines)-1] != line {
				lines = append(lines, line)
			}
		}
	}
	return lines
}

// releaseVersionMentionOffsets returns the byte offsets in text where the
// release version occurs as a whole version number, with or without its "v".
// A mention must not be part of a longer number or word: "1.8.20", "1.8.2.1",
// "11.8.2", "10.1.8.2" and "dev1.8.2" are not mentions of 1.8.2, while an
// archive name ("leakwatch_1.8.2_linux"), an image tag ("1.8.2-amd64"), a URL
// ("/tag/v1.8.2") and a sentence end ("v1.8.2.") are.
func releaseVersionMentionOffsets(text, version string) []int {
	bare := strings.TrimPrefix(version, "v")
	var offsets []int
	for from := 0; from < len(text); {
		index := strings.Index(text[from:], bare)
		if index < 0 {
			break
		}
		start := from + index
		end := start + len(bare)
		from = end
		if versionMentionBoundaryBefore(text, start) && versionMentionBoundaryAfter(text, end) {
			offsets = append(offsets, start)
		}
	}
	return offsets
}

func versionMentionBoundaryBefore(text string, start int) bool {
	if start > 0 && text[start-1] == 'v' {
		start--
	}
	if start == 0 {
		return true
	}
	previous := text[start-1]
	return previous != '.' && !isASCIIAlphanumeric(previous)
}

// versionMentionBoundaryAfter treats a hyphen as a boundary on purpose: an image
// tag such as "1.8.2-amd64" is a mention of 1.8.2, and a pre-release suffix
// cannot be told apart from an architecture suffix. A real pre-release of the
// previous release is reported too and takes the historical marker; a loud
// false positive is cheaper than a stale version slipping through.
func versionMentionBoundaryAfter(text string, end int) bool {
	if end >= len(text) {
		return true
	}
	next := text[end]
	if next == '.' {
		return end+1 >= len(text) || !isASCIIDigit(text[end+1])
	}
	return !isASCIIAlphanumeric(next)
}

func isASCIIDigit(b byte) bool { return b >= '0' && b <= '9' }

func isASCIIAlphanumeric(b byte) bool {
	return isASCIIDigit(b) || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}
