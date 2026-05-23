// Package slack provides a Slack workspace scan source.
package slack

import "time"

// Option configures a SlackSource.
type Option func(*SlackSource)

// WithChannels limits the scan to the specified channel names
// (e.g. "engineering"), matching the names shown in Slack and accepted by the
// --channels CLI flag.
func WithChannels(channels []string) Option {
	return func(s *SlackSource) {
		s.channels = channels
	}
}

// WithExcludeChannels excludes the specified channel names from scanning,
// matching the names shown in Slack and accepted by the --exclude-channels
// CLI flag.
func WithExcludeChannels(channels []string) Option {
	return func(s *SlackSource) {
		s.excludeChannels = channels
	}
}

// WithSince limits the scan to messages after the given time.
func WithSince(t time.Time) Option {
	return func(s *SlackSource) {
		s.since = t
	}
}

// WithIncludeDMs enables or disables scanning of direct messages.
func WithIncludeDMs(include bool) Option {
	return func(s *SlackSource) {
		s.includeDMs = include
	}
}

// WithIncludeFiles requests scanning of file content.
//
// NOTE: Slack file scanning is not yet implemented. This option is currently a
// no-op for actual scanning behavior (only message text is scanned); enabling
// it causes a warning to be logged. See ROADMAP and the planned-feature note in slack.go.
func WithIncludeFiles(include bool) Option {
	return func(s *SlackSource) {
		s.includeFiles = include
	}
}

// WithRateLimit sets the Slack API rate limit in requests per second.
func WithRateLimit(rps float64) Option {
	return func(s *SlackSource) {
		if rps > 0 {
			s.rateLimit = rps
		}
	}
}

// WithBufferSize sets the channel buffer size for the chunk channel.
func WithBufferSize(size int) Option {
	return func(s *SlackSource) {
		if size > 0 {
			s.bufferSize = size
		}
	}
}
