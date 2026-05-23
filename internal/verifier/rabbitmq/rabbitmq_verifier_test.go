package rabbitmq

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cemililik/leakwatch/internal/detector"
	"github.com/cemililik/leakwatch/pkg/finding"
)

func TestVerifier_Type_ReturnsCorrectID(t *testing.T) {
	v := &Verifier{}
	assert.Equal(t, "rabbitmq-connection-string", v.Type())
}

func TestVerify_ValidAMQPURL_ReturnsUnverified(t *testing.T) {
	v := &Verifier{}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("amqp://admin:s3cret@rabbitmq.example.com:5672/"),
		Redacted:   "amqp://admin:****@rabbitmq.example.com:5672/",
	}

	result := v.Verify(context.Background(), raw)

	// Format-only verifier: a valid URL does not prove the broker is reachable
	// or the credentials active, so the status must be Unverified.
	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Contains(t, result.Message, "format valid")
	assert.Equal(t, "rabbitmq.example.com", result.ExtraData["host"])
	assert.Equal(t, "admin", result.ExtraData["user"])
}

func TestVerify_ValidAMQPSURL_ReturnsUnverified(t *testing.T) {
	v := &Verifier{}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("amqps://myuser:mypass@broker.cloud.io:5671/production"),
		Redacted:   "amqps://myuser:****@broker.cloud.io:5671/production",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Equal(t, "broker.cloud.io", result.ExtraData["host"])
	assert.Equal(t, "myuser", result.ExtraData["user"])
}

func TestVerify_WrongScheme_ReturnsUnverified(t *testing.T) {
	v := &Verifier{}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("http://admin:pass@rabbitmq.example.com:5672/"),
		Redacted:   "****",
	}

	result := v.Verify(context.Background(), raw)

	// Format invalid must NOT be VerifiedInactive: no provider was contacted.
	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Contains(t, result.Message, "format invalid")
}

func TestVerify_MissingCredentials_ReturnsUnverified(t *testing.T) {
	v := &Verifier{}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("amqp://rabbitmq.example.com:5672/"),
		Redacted:   "****",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Contains(t, result.Message, "format invalid")
}

func TestVerify_MissingHost_ReturnsUnverified(t *testing.T) {
	v := &Verifier{}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("amqp://user:pass@"),
		Redacted:   "****",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Contains(t, result.Message, "format invalid")
}

func TestVerify_EmptyInput_ReturnsUnverified(t *testing.T) {
	v := &Verifier{}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte(""),
		Redacted:   "",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Equal(t, "empty connection string", result.Message)
}

func TestVerify_InvalidURL_ReturnsUnverified(t *testing.T) {
	v := &Verifier{}

	raw := detector.RawFinding{
		DetectorID: detectorID,
		Raw:        []byte("://not-a-valid-url"),
		Redacted:   "****",
	}

	result := v.Verify(context.Background(), raw)

	assert.Equal(t, finding.StatusUnverified, result.Status)
	assert.Contains(t, result.Message, "format invalid")
}
