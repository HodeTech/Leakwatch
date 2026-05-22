package slack

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/slack-go/slack"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockSlackClient is a minimal mock for the slackClient interface.
type mockSlackClient struct {
	channels   []slack.Channel
	messages   map[string][]slack.Message
	authErr    error
	listErr    error
	historyErr error

	// lastHistoryOldest records the Oldest parameter from the most recent
	// GetConversationHistoryContext call, for assertions.
	lastHistoryOldest string
}

func (m *mockSlackClient) AuthTestContext(_ context.Context) (*slack.AuthTestResponse, error) {
	if m.authErr != nil {
		return nil, m.authErr
	}
	return &slack.AuthTestResponse{}, nil
}

func (m *mockSlackClient) GetConversationsContext(_ context.Context, params *slack.GetConversationsParameters) ([]slack.Channel, string, error) {
	if m.listErr != nil {
		return nil, "", m.listErr
	}
	// Simple: return all channels on first call, empty cursor means no more pages.
	if params.Cursor == "" {
		return m.channels, "", nil
	}
	return nil, "", nil
}

func (m *mockSlackClient) GetConversationHistoryContext(_ context.Context, params *slack.GetConversationHistoryParameters) (*slack.GetConversationHistoryResponse, error) {
	m.lastHistoryOldest = params.Oldest
	if m.historyErr != nil {
		return nil, m.historyErr
	}

	msgs, ok := m.messages[params.ChannelID]
	if !ok {
		return &slack.GetConversationHistoryResponse{
			HasMore:       false,
			Messages:      nil,
			SlackResponse: slack.SlackResponse{Ok: true},
		}, nil
	}

	return &slack.GetConversationHistoryResponse{
		HasMore:       false,
		Messages:      msgs,
		SlackResponse: slack.SlackResponse{Ok: true},
	}, nil
}

func TestSlackSource_Type_ReturnsSlack(t *testing.T) {
	s := New("xoxb-test-token")
	assert.Equal(t, "slack", s.Type())
}

func TestSlackSource_Validate_ValidToken_ReturnsNoError(t *testing.T) {
	s := New("xoxb-test-token")
	s.client = &mockSlackClient{}

	err := s.Validate()
	assert.NoError(t, err)
}

func TestSlackSource_Validate_InvalidToken_ReturnsError(t *testing.T) {
	s := New("xoxb-bad-token")
	s.client = &mockSlackClient{
		authErr: fmt.Errorf("invalid_auth"),
	}

	err := s.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "slack auth test failed")
	assert.Contains(t, err.Error(), "invalid_auth")
}

func TestSlackSource_Validate_EmptyToken_ReturnsError(t *testing.T) {
	s := New("")

	err := s.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "slack token is required")
}

func TestSlackSource_Chunks_SingleChannel_EmitsMessages(t *testing.T) {
	mock := &mockSlackClient{
		channels: []slack.Channel{
			{GroupConversation: slack.GroupConversation{Conversation: slack.Conversation{ID: "C001"}, Name: "general"}},
		},
		messages: map[string][]slack.Message{
			"C001": {
				{Msg: slack.Msg{Text: "here is my API_KEY=sk-abc123", User: "U001", Timestamp: "1700000001.000000"}},
				{Msg: slack.Msg{Text: "another message with SECRET=xyz", User: "U002", Timestamp: "1700000002.000000"}},
			},
		},
	}

	s := New("xoxb-test-token")
	s.client = mock

	ctx := context.Background()
	var chunks []string
	var metas []string
	for chunk := range s.Chunks(ctx) {
		chunks = append(chunks, string(chunk.Data))
		metas = append(metas, chunk.SourceMetadata.Channel)
	}

	assert.Len(t, chunks, 2)
	assert.Contains(t, chunks, "here is my API_KEY=sk-abc123")
	assert.Contains(t, chunks, "another message with SECRET=xyz")
	// All chunks should reference channel C001.
	for _, m := range metas {
		assert.Equal(t, "C001", m)
	}
}

func TestSlackSource_Chunks_ChannelFilter_OnlyMatchingChannels(t *testing.T) {
	mock := &mockSlackClient{
		channels: []slack.Channel{
			{GroupConversation: slack.GroupConversation{Conversation: slack.Conversation{ID: "C001"}, Name: "general"}},
			{GroupConversation: slack.GroupConversation{Conversation: slack.Conversation{ID: "C002"}, Name: "random"}},
			{GroupConversation: slack.GroupConversation{Conversation: slack.Conversation{ID: "C003"}, Name: "secrets"}},
		},
		messages: map[string][]slack.Message{
			"C001": {{Msg: slack.Msg{Text: "msg from general", User: "U001", Timestamp: "1700000001.000000"}}},
			"C002": {{Msg: slack.Msg{Text: "msg from random", User: "U001", Timestamp: "1700000001.000000"}}},
			"C003": {{Msg: slack.Msg{Text: "msg from secrets", User: "U001", Timestamp: "1700000001.000000"}}},
		},
	}

	// Filters are matched against channel names, not IDs.
	s := New("xoxb-test-token", WithChannels([]string{"general", "secrets"}))
	s.client = mock

	ctx := context.Background()
	var channelIDs []string
	for chunk := range s.Chunks(ctx) {
		channelIDs = append(channelIDs, chunk.SourceMetadata.Channel)
	}

	assert.Len(t, channelIDs, 2)
	assert.Contains(t, channelIDs, "C001")
	assert.Contains(t, channelIDs, "C003")
	assert.NotContains(t, channelIDs, "C002")
}

func TestSlackSource_Chunks_ChannelFilter_ByID_MatchesNothing(t *testing.T) {
	mock := &mockSlackClient{
		channels: []slack.Channel{
			{GroupConversation: slack.GroupConversation{Conversation: slack.Conversation{ID: "C001"}, Name: "general"}},
			{GroupConversation: slack.GroupConversation{Conversation: slack.Conversation{ID: "C002"}, Name: "random"}},
		},
		messages: map[string][]slack.Message{
			"C001": {{Msg: slack.Msg{Text: "msg from general", User: "U001", Timestamp: "1700000001.000000"}}},
			"C002": {{Msg: slack.Msg{Text: "msg from random", User: "U001", Timestamp: "1700000001.000000"}}},
		},
	}

	// Passing channel IDs (not names) must not match any channel.
	s := New("xoxb-test-token", WithChannels([]string{"C001"}))
	s.client = mock

	ctx := context.Background()
	count := 0
	for range s.Chunks(ctx) {
		count++
	}

	assert.Equal(t, 0, count)
}

func TestSlackSource_Chunks_ExcludeChannels_SkipsExcluded(t *testing.T) {
	mock := &mockSlackClient{
		channels: []slack.Channel{
			{GroupConversation: slack.GroupConversation{Conversation: slack.Conversation{ID: "C001"}, Name: "general"}},
			{GroupConversation: slack.GroupConversation{Conversation: slack.Conversation{ID: "C002"}, Name: "random"}},
			{GroupConversation: slack.GroupConversation{Conversation: slack.Conversation{ID: "C003"}, Name: "secrets"}},
		},
		messages: map[string][]slack.Message{
			"C001": {{Msg: slack.Msg{Text: "msg from general", User: "U001", Timestamp: "1700000001.000000"}}},
			"C002": {{Msg: slack.Msg{Text: "msg from random", User: "U001", Timestamp: "1700000001.000000"}}},
			"C003": {{Msg: slack.Msg{Text: "msg from secrets", User: "U001", Timestamp: "1700000001.000000"}}},
		},
	}

	// Exclude filters are matched against channel names, not IDs.
	s := New("xoxb-test-token", WithExcludeChannels([]string{"random"}))
	s.client = mock

	ctx := context.Background()
	var channelIDs []string
	for chunk := range s.Chunks(ctx) {
		channelIDs = append(channelIDs, chunk.SourceMetadata.Channel)
	}

	assert.Len(t, channelIDs, 2)
	assert.Contains(t, channelIDs, "C001")
	assert.Contains(t, channelIDs, "C003")
	assert.NotContains(t, channelIDs, "C002")
}

func TestSlackSource_Chunks_SinceFilter_SkipsOldMessages(t *testing.T) {
	// Timestamp 1700000000 = 2023-11-14T22:13:20Z
	// Timestamp 1600000000 = 2020-09-13T12:26:40Z
	mock := &mockSlackClient{
		channels: []slack.Channel{
			{GroupConversation: slack.GroupConversation{Conversation: slack.Conversation{ID: "C001"}, Name: "general"}},
		},
		messages: map[string][]slack.Message{
			"C001": {
				{Msg: slack.Msg{Text: "old message", User: "U001", Timestamp: "1600000000.000000"}},
				{Msg: slack.Msg{Text: "new message", User: "U002", Timestamp: "1700000000.000000"}},
			},
		},
	}

	sinceTime := time.Unix(1650000000, 0) // 2022-04-15
	s := New("xoxb-test-token", WithSince(sinceTime))
	s.client = mock

	ctx := context.Background()
	var chunks []string
	for chunk := range s.Chunks(ctx) {
		chunks = append(chunks, string(chunk.Data))
	}

	assert.Len(t, chunks, 1)
	assert.Equal(t, "new message", chunks[0])
}

func TestSlackSource_Chunks_SinceFilter_SetsOldestParam(t *testing.T) {
	mock := &mockSlackClient{
		channels: []slack.Channel{
			{GroupConversation: slack.GroupConversation{Conversation: slack.Conversation{ID: "C001"}, Name: "general"}},
		},
		messages: map[string][]slack.Message{
			"C001": {{Msg: slack.Msg{Text: "new message", User: "U001", Timestamp: "1700000000.000000"}}},
		},
	}

	sinceTime := time.Unix(1650000000, 0)
	s := New("xoxb-test-token", WithSince(sinceTime))
	s.client = mock

	ctx := context.Background()
	for range s.Chunks(ctx) { //nolint:revive // drain channel
	}

	// The since filter must be pushed down to the API via Oldest.
	assert.Equal(t, "1650000000.000000", mock.lastHistoryOldest)
}

func TestSlackSource_Chunks_NoSince_DoesNotSetOldest(t *testing.T) {
	mock := &mockSlackClient{
		channels: []slack.Channel{
			{GroupConversation: slack.GroupConversation{Conversation: slack.Conversation{ID: "C001"}, Name: "general"}},
		},
		messages: map[string][]slack.Message{
			"C001": {{Msg: slack.Msg{Text: "message", User: "U001", Timestamp: "1700000000.000000"}}},
		},
	}

	s := New("xoxb-test-token")
	s.client = mock

	ctx := context.Background()
	for range s.Chunks(ctx) { //nolint:revive // drain channel
	}

	assert.Empty(t, mock.lastHistoryOldest)
}

func TestFormatSlackTimestamp_ProducesSlackFormat(t *testing.T) {
	got := formatSlackTimestamp(time.Unix(1650000000, 0))
	assert.Equal(t, "1650000000.000000", got)
}

func TestSlackSource_New_IncludeFilesDefaultsFalse(t *testing.T) {
	s := New("xoxb-test-token")
	assert.False(t, s.includeFiles)
}

func TestSlackSource_Chunks_IncludeFiles_ScansTextOnly(t *testing.T) {
	// File scanning is not implemented; enabling WithIncludeFiles must not
	// change the emitted chunks (still text-only) and must not error.
	mock := &mockSlackClient{
		channels: []slack.Channel{
			{GroupConversation: slack.GroupConversation{Conversation: slack.Conversation{ID: "C001"}, Name: "general"}},
		},
		messages: map[string][]slack.Message{
			"C001": {{Msg: slack.Msg{Text: "hello", User: "U001", Timestamp: "1700000001.000000"}}},
		},
	}

	s := New("xoxb-test-token", WithIncludeFiles(true))
	s.client = mock

	ctx := context.Background()
	var chunks []string
	for chunk := range s.Chunks(ctx) {
		chunks = append(chunks, string(chunk.Data))
	}

	assert.Equal(t, []string{"hello"}, chunks)
}

func TestSlackSource_Chunks_ContextCancellation_Stops(t *testing.T) {
	mock := &mockSlackClient{
		channels: []slack.Channel{
			{GroupConversation: slack.GroupConversation{Conversation: slack.Conversation{ID: "C001"}, Name: "general"}},
			{GroupConversation: slack.GroupConversation{Conversation: slack.Conversation{ID: "C002"}, Name: "random"}},
			{GroupConversation: slack.GroupConversation{Conversation: slack.Conversation{ID: "C003"}, Name: "dev"}},
		},
		messages: map[string][]slack.Message{
			"C001": {{Msg: slack.Msg{Text: "msg1", User: "U001", Timestamp: "1700000001.000000"}}},
			"C002": {{Msg: slack.Msg{Text: "msg2", User: "U001", Timestamp: "1700000001.000000"}}},
			"C003": {{Msg: slack.Msg{Text: "msg3", User: "U001", Timestamp: "1700000001.000000"}}},
		},
	}

	s := New("xoxb-test-token", WithBufferSize(1))
	s.client = mock

	ctx, cancel := context.WithCancel(context.Background())
	ch := s.Chunks(ctx)

	// Read one chunk then cancel.
	<-ch
	cancel()

	// Drain the channel; it must close.
	count := 0
	for range ch {
		count++
	}
	// Some buffered chunks may arrive, but the channel must close.
	assert.Less(t, count, 3)
}

func TestSlackSource_Chunks_EmptyWorkspace_NoChunks(t *testing.T) {
	mock := &mockSlackClient{
		channels: []slack.Channel{},
		messages: map[string][]slack.Message{},
	}

	s := New("xoxb-test-token")
	s.client = mock

	ctx := context.Background()
	count := 0
	for range s.Chunks(ctx) {
		count++
	}

	assert.Equal(t, 0, count)
}

func TestSlackSource_Chunks_SourceMetadata_Format(t *testing.T) {
	mock := &mockSlackClient{
		channels: []slack.Channel{
			{GroupConversation: slack.GroupConversation{Conversation: slack.Conversation{ID: "C001"}, Name: "general"}},
		},
		messages: map[string][]slack.Message{
			"C001": {
				{Msg: slack.Msg{
					Text:            "leaked secret here",
					User:            "U123",
					Timestamp:       "1700000001.000100",
					ThreadTimestamp: "1700000000.000000",
				}},
			},
		},
	}

	s := New("xoxb-test-token")
	s.client = mock

	ctx := context.Background()
	var chunk []byte
	var meta string
	var channelName, user, ts, threadTS string
	for c := range s.Chunks(ctx) {
		chunk = c.Data
		meta = c.SourceMetadata.SourceType
		channelName = c.SourceMetadata.ChannelName
		user = c.SourceMetadata.MessageUser
		ts = c.SourceMetadata.MessageTS
		threadTS = c.SourceMetadata.ThreadTS
	}

	assert.Equal(t, "slack", meta)
	assert.Equal(t, "leaked secret here", string(chunk))
	assert.Equal(t, "general", channelName)
	assert.Equal(t, "U123", user)
	assert.Equal(t, "1700000001.000100", ts)
	assert.Equal(t, "1700000000.000000", threadTS)
}
