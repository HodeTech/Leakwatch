// Package slack provides a Slack workspace scan source.
package slack

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/slack-go/slack"
	"golang.org/x/time/rate"

	"github.com/cemililik/leakwatch/internal/source"
	"github.com/cemililik/leakwatch/pkg/finding"
)

const (
	defaultRateLimit  = 20.0
	defaultBufferSize = 100
)

// SlackSource scans messages in a Slack workspace for leaked secrets.
type SlackSource struct {
	token           string
	channels        []string
	excludeChannels []string
	since           time.Time
	includeDMs      bool
	includeFiles    bool
	rateLimit       float64
	bufferSize      int
	client          slackClient
	newClient       func(token string) slackClient
}

// defaultNewClient creates a real Slack API client.
func defaultNewClient(token string) slackClient {
	return slack.New(token)
}

// New creates a new SlackSource for the given workspace token.
// Use functional options to configure channel filtering, rate limits, etc.
func New(token string, opts ...Option) *SlackSource {
	s := &SlackSource{
		token:        token,
		includeDMs:   false,
		includeFiles: true,
		rateLimit:    defaultRateLimit,
		bufferSize:   defaultBufferSize,
		newClient:    defaultNewClient,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Type returns the source type identifier.
func (s *SlackSource) Type() string {
	return "slack"
}

// Validate checks that the Slack token is valid by calling AuthTest.
func (s *SlackSource) Validate() error {
	if s.token == "" {
		return fmt.Errorf("slack token is required")
	}

	s.ensureClient()

	_, err := s.client.AuthTestContext(context.Background())
	if err != nil {
		return fmt.Errorf("slack auth test failed: %w", err)
	}

	return nil
}

// Chunks lists channels in the workspace and sends message contents over a channel.
// The channel is closed when all messages have been processed or the context is cancelled.
func (s *SlackSource) Chunks(ctx context.Context) <-chan source.Chunk {
	ch := make(chan source.Chunk, s.bufferSize)
	go func() {
		defer close(ch)

		s.ensureClient()

		limiter := rate.NewLimiter(rate.Limit(s.rateLimit), 1)

		channels, err := s.listChannels(ctx, limiter)
		if err != nil {
			slog.Error("slack channel listing failed", "error", err)
			return
		}

		channels = s.filterChannels(channels)

		for _, channel := range channels {
			select {
			case <-ctx.Done():
				return
			default:
			}

			s.processChannel(ctx, ch, limiter, channel)
		}
	}()
	return ch
}

// ensureClient initializes the Slack client if not already set.
func (s *SlackSource) ensureClient() {
	if s.client != nil {
		return
	}
	s.client = s.newClient(s.token)
}

// listChannels retrieves all accessible channels via paginated API calls.
func (s *SlackSource) listChannels(ctx context.Context, limiter *rate.Limiter) ([]slack.Channel, error) {
	var allChannels []slack.Channel
	cursor := ""

	for {
		select {
		case <-ctx.Done():
			return allChannels, ctx.Err()
		default:
		}

		if err := limiter.Wait(ctx); err != nil {
			return allChannels, fmt.Errorf("slack rate limiter wait: %w", err)
		}

		types := []string{"public_channel", "private_channel"}
		if s.includeDMs {
			types = append(types, "im", "mpim")
		}

		params := &slack.GetConversationsParameters{
			Types:  types,
			Cursor: cursor,
			Limit:  200,
		}

		channels, nextCursor, err := s.client.GetConversationsContext(ctx, params)
		if err != nil {
			return nil, fmt.Errorf("slack list conversations: %w", err)
		}

		allChannels = append(allChannels, channels...)

		if nextCursor == "" {
			break
		}
		cursor = nextCursor
	}

	return allChannels, nil
}

// filterChannels applies include/exclude channel filters.
func (s *SlackSource) filterChannels(channels []slack.Channel) []slack.Channel {
	if len(s.channels) == 0 && len(s.excludeChannels) == 0 {
		return channels
	}

	includeSet := make(map[string]struct{}, len(s.channels))
	for _, id := range s.channels {
		includeSet[id] = struct{}{}
	}

	excludeSet := make(map[string]struct{}, len(s.excludeChannels))
	for _, id := range s.excludeChannels {
		excludeSet[id] = struct{}{}
	}

	var filtered []slack.Channel
	for _, ch := range channels {
		if _, excluded := excludeSet[ch.ID]; excluded {
			continue
		}
		if len(includeSet) > 0 {
			if _, included := includeSet[ch.ID]; !included {
				continue
			}
		}
		filtered = append(filtered, ch)
	}

	return filtered
}

// processChannel reads message history for a single channel and emits chunks.
func (s *SlackSource) processChannel(ctx context.Context, ch chan<- source.Chunk, limiter *rate.Limiter, channel slack.Channel) {
	cursor := ""

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if err := limiter.Wait(ctx); err != nil {
			slog.Warn("slack rate limiter wait failed", "channel", channel.ID, "error", err)
			return
		}

		params := &slack.GetConversationHistoryParameters{
			ChannelID: channel.ID,
			Cursor:    cursor,
			Limit:     200,
		}

		resp, err := s.client.GetConversationHistoryContext(ctx, params)
		if err != nil {
			slog.Warn("slack conversation history failed", "channel", channel.ID, "error", err)
			return
		}

		for _, msg := range resp.Messages {
			select {
			case <-ctx.Done():
				return
			default:
			}

			// Apply since filter by parsing the message timestamp.
			if !s.since.IsZero() {
				msgTime := parseSlackTimestamp(msg.Timestamp)
				if msgTime.Before(s.since) {
					continue
				}
			}

			if msg.Text == "" {
				continue
			}

			select {
			case ch <- source.Chunk{
				Data: []byte(msg.Text),
				SourceMetadata: finding.SourceMetadata{
					SourceType:  "slack",
					Channel:     channel.ID,
					ChannelName: channel.Name,
					MessageUser: msg.User,
					MessageTS:   msg.Timestamp,
					ThreadTS:    msg.ThreadTimestamp,
				},
			}:
			case <-ctx.Done():
				return
			}
		}

		if !resp.HasMore {
			return
		}
		cursor = resp.ResponseMetaData.NextCursor
	}
}

// parseSlackTimestamp converts a Slack message timestamp (e.g., "1234567890.123456")
// to a time.Time. Returns zero time on parse failure.
func parseSlackTimestamp(ts string) time.Time {
	if ts == "" {
		return time.Time{}
	}

	sec, err := strconv.ParseFloat(ts, 64)
	if err != nil {
		return time.Time{}
	}

	return time.Unix(int64(sec), 0)
}
