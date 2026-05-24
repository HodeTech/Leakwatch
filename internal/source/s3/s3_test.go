package s3

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/HodeTech/leakwatch/internal/source"
)

// mockS3Client is a minimal mock for the s3Client interface.
type mockS3Client struct {
	objects []types.Object
	data    map[string]string
	headErr error
}

func (m *mockS3Client) ListObjectsV2(_ context.Context, input *s3.ListObjectsV2Input, _ ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	var filtered []types.Object
	for _, obj := range m.objects {
		if input.Prefix != nil && obj.Key != nil && !strings.HasPrefix(*obj.Key, *input.Prefix) {
			continue
		}
		filtered = append(filtered, obj)
	}
	return &s3.ListObjectsV2Output{
		Contents: filtered,
	}, nil
}

func (m *mockS3Client) GetObject(_ context.Context, input *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	key := *input.Key
	content, ok := m.data[key]
	if !ok {
		content = ""
	}
	return &s3.GetObjectOutput{
		Body: io.NopCloser(strings.NewReader(content)),
	}, nil
}

func (m *mockS3Client) HeadBucket(_ context.Context, _ *s3.HeadBucketInput, _ ...func(*s3.Options)) (*s3.HeadBucketOutput, error) {
	return &s3.HeadBucketOutput{}, m.headErr
}

func ptr[T any](v T) *T {
	return &v
}

func TestS3Source_Type_ReturnsS3(t *testing.T) {
	s := New("my-bucket")
	assert.Equal(t, "s3", s.Type())
}

func TestS3Source_New_DefaultValues(t *testing.T) {
	s := New("my-bucket")
	assert.Equal(t, "my-bucket", s.bucket)
	assert.Equal(t, int64(10*1024*1024), s.maxFileSize)
	assert.Equal(t, 64, s.bufferSize)
	assert.Empty(t, s.prefix)
}

func TestS3Source_New_WithOptions(t *testing.T) {
	s := New(
		"my-bucket",
		WithPrefix("logs/"),
		WithMaxFileSize(5*1024*1024),
		WithBufferSize(32),
		WithRegion("us-west-2"),
	)
	assert.Equal(t, "logs/", s.prefix)
	assert.Equal(t, int64(5*1024*1024), s.maxFileSize)
	assert.Equal(t, 32, s.bufferSize)
	assert.Equal(t, "us-west-2", s.region)
}

func TestS3Source_Validate_EmptyBucket_ReturnsError(t *testing.T) {
	s := New("")
	err := s.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bucket name is required")
}

func TestS3Source_Validate_AccessibleBucket_ReturnsNil(t *testing.T) {
	s := New("my-bucket")
	s.client = &mockS3Client{}
	assert.NoError(t, s.Validate())
}

func TestS3Source_Chunks_SendsTextObjects(t *testing.T) {
	mock := &mockS3Client{
		objects: []types.Object{
			{Key: ptr("config.yaml"), Size: ptr(int64(20))},
			{Key: ptr("secret.txt"), Size: ptr(int64(15))},
		},
		data: map[string]string{
			"config.yaml": "api_key: test123",
			"secret.txt":  "password=hunter2",
		},
	}

	s := New("my-bucket")
	s.client = mock

	ctx := context.Background()
	var chunks []string
	for chunk := range s.Chunks(ctx) {
		chunks = append(chunks, chunk.SourceMetadata.FilePath)
	}

	assert.Len(t, chunks, 2)
	assert.Contains(t, chunks, "my-bucket/config.yaml")
	assert.Contains(t, chunks, "my-bucket/secret.txt")
}

func TestS3Source_Chunks_SkipsBinaryExtensions(t *testing.T) {
	mock := &mockS3Client{
		objects: []types.Object{
			{Key: ptr("code.go"), Size: ptr(int64(20))},
			{Key: ptr("image.png"), Size: ptr(int64(20))},
		},
		data: map[string]string{
			"code.go": "package main",
		},
	}

	s := New("my-bucket")
	s.client = mock

	ctx := context.Background()
	var chunks []string
	for chunk := range s.Chunks(ctx) {
		chunks = append(chunks, chunk.SourceMetadata.FilePath)
	}

	assert.Len(t, chunks, 1)
	assert.Equal(t, "my-bucket/code.go", chunks[0])
}

func TestS3Source_Chunks_SkipsLargeObjects(t *testing.T) {
	mock := &mockS3Client{
		objects: []types.Object{
			{Key: ptr("small.txt"), Size: ptr(int64(100))},
			{Key: ptr("big.txt"), Size: ptr(int64(20 * 1024 * 1024))},
		},
		data: map[string]string{
			"small.txt": "small content",
		},
	}

	s := New("my-bucket", WithMaxFileSize(1024*1024))
	s.client = mock

	ctx := context.Background()
	var chunks []string
	for chunk := range s.Chunks(ctx) {
		chunks = append(chunks, chunk.SourceMetadata.FilePath)
	}

	assert.Len(t, chunks, 1)
	assert.Equal(t, "my-bucket/small.txt", chunks[0])
}

func TestS3Source_Chunks_SkipsBinaryContent(t *testing.T) {
	mock := &mockS3Client{
		objects: []types.Object{
			{Key: ptr("text.txt"), Size: ptr(int64(11))},
			{Key: ptr("binary.dat"), Size: ptr(int64(11))},
		},
		data: map[string]string{
			"text.txt":   "hello world",
			"binary.dat": "hello\x00world",
		},
	}

	s := New("my-bucket")
	s.client = mock

	ctx := context.Background()
	var chunks []string
	for chunk := range s.Chunks(ctx) {
		chunks = append(chunks, chunk.SourceMetadata.FilePath)
	}

	assert.Len(t, chunks, 1)
	assert.Equal(t, "my-bucket/text.txt", chunks[0])
}

func TestS3Source_Chunks_ContextCancellation(t *testing.T) {
	mock := &mockS3Client{
		objects: []types.Object{
			{Key: ptr("a.txt"), Size: ptr(int64(5))},
			{Key: ptr("b.txt"), Size: ptr(int64(5))},
			{Key: ptr("c.txt"), Size: ptr(int64(5))},
		},
		data: map[string]string{
			"a.txt": "aaa",
			"b.txt": "bbb",
			"c.txt": "ccc",
		},
	}

	s := New("my-bucket", WithBufferSize(1))
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

func TestS3Source_Chunks_SourceMetadata_Format(t *testing.T) {
	mock := &mockS3Client{
		objects: []types.Object{
			{Key: ptr("path/to/file.env"), Size: ptr(int64(10))},
		},
		data: map[string]string{
			"path/to/file.env": "SECRET=abc",
		},
	}

	s := New("my-bucket")
	s.client = mock

	ctx := context.Background()
	var chunk source.Chunk
	for chunk = range s.Chunks(ctx) {
	}

	assert.Equal(t, "s3", chunk.SourceMetadata.SourceType)
	assert.Equal(t, "my-bucket/path/to/file.env", chunk.SourceMetadata.FilePath)
}

func TestS3Source_Chunks_BoundsReadToMaxFileSize(t *testing.T) {
	// The listed size understates the real body so the listing-based size
	// check passes, but the bounded read must still drop the oversize object.
	bigBody := strings.Repeat("A", 2048)
	mock := &mockS3Client{
		objects: []types.Object{
			{Key: ptr("small.txt"), Size: ptr(int64(5))},
			{Key: ptr("liar.txt"), Size: ptr(int64(5))},
		},
		data: map[string]string{
			"small.txt": "hello",
			"liar.txt":  bigBody,
		},
	}

	s := New("my-bucket", WithMaxFileSize(1024))
	s.client = mock

	ctx := context.Background()
	var chunks []string
	for chunk := range s.Chunks(ctx) {
		chunks = append(chunks, chunk.SourceMetadata.FilePath)
	}

	assert.Len(t, chunks, 1)
	assert.Equal(t, "my-bucket/small.txt", chunks[0])
}

func TestS3Source_DownloadObject_AtLimit_NotSkipped(t *testing.T) {
	body := strings.Repeat("A", 1024)
	mock := &mockS3Client{
		data: map[string]string{"exact.txt": body},
	}
	s := New("my-bucket", WithMaxFileSize(1024))
	s.client = mock

	data, err := s.downloadObject(context.Background(), "exact.txt")
	require.NoError(t, err)
	assert.Len(t, data, 1024)
}

func TestS3Source_Chunks_WithExcludePaths_FiltersObjects(t *testing.T) {
	mock := &mockS3Client{
		objects: []types.Object{
			{Key: ptr("src/app.go"), Size: ptr(int64(10))},
			{Key: ptr("vendor/lib.go"), Size: ptr(int64(10))},
			{Key: ptr("test/data.txt"), Size: ptr(int64(10))},
		},
		data: map[string]string{
			"src/app.go":    "package app",
			"vendor/lib.go": "package lib",
			"test/data.txt": "fixture",
		},
	}

	s := New("my-bucket", WithExcludePaths([]string{"vendor/**", "test/*"}))
	s.client = mock

	ctx := context.Background()
	var chunks []string
	for chunk := range s.Chunks(ctx) {
		chunks = append(chunks, chunk.SourceMetadata.FilePath)
	}

	assert.Len(t, chunks, 1)
	assert.Equal(t, "my-bucket/src/app.go", chunks[0])
}

func TestS3Source_New_WithExcludePaths_StoresPatterns(t *testing.T) {
	s := New("my-bucket", WithExcludePaths([]string{"a/**", "b"}))
	assert.Equal(t, []string{"a/**", "b"}, s.excludePaths)
}

func TestS3Source_Chunks_WithPrefix_FiltersObjects(t *testing.T) {
	mock := &mockS3Client{
		objects: []types.Object{
			{Key: ptr("logs/app.log"), Size: ptr(int64(10))},
			{Key: ptr("config/app.yaml"), Size: ptr(int64(10))},
		},
		data: map[string]string{
			"config/app.yaml": "key: value",
		},
	}

	s := New("my-bucket", WithPrefix("config/"))
	s.client = mock

	ctx := context.Background()
	var chunks []string
	for chunk := range s.Chunks(ctx) {
		chunks = append(chunks, chunk.SourceMetadata.FilePath)
	}

	assert.Len(t, chunks, 1)
	assert.Equal(t, "my-bucket/config/app.yaml", chunks[0])
}
