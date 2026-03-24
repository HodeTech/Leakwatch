// Package slack provides a Slack workspace scan source.
package slack

import "time"

// Option configures a SlackSource.
type Option func(*SlackSource)

// WithChannels limits the scan to the specified channel IDs.
func WithChannels(channels []string) Option {
	return func(s *SlackSource) {
		s.channels = channels
	}
}

// WithExcludeChannels excludes the specified channel IDs from scanning.
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

// WithIncludeFiles enables or disables scanning of file content.
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
