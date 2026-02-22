package telemetry

import (
	"encoding/json"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildMetricsPayloadAt(t *testing.T) {
	startup := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := time.Date(2026, 1, 1, 0, 30, 0, 0, time.UTC)

	payload := BuildMetricsPayloadAt("2.2.0", startup, 1800, 500, now)
	require.Len(t, payload.RemediationComponents, 1)

	c := payload.RemediationComponents[0]
	assert.Equal(t, "cs-abuseipdb-bouncer", c.Type)
	assert.Equal(t, "v2.2.0", c.Version)
	assert.Equal(t, runtime.GOOS, c.OS.Name)
	assert.Equal(t, runtime.GOARCH, c.OS.Version)
	assert.Equal(t, int64(1800), c.Meta.WindowSizeSeconds)
	assert.Equal(t, startup.Unix(), c.Meta.UtcStartupTimestamp)
	assert.Equal(t, now.Unix(), c.Meta.UtcNowTimestamp)
	require.Len(t, c.Metrics, 1)
	assert.Equal(t, "processed", c.Metrics[0].Name)
	assert.Equal(t, int64(500), c.Metrics[0].Value)
	assert.Equal(t, "request", c.Metrics[0].Unit)

	_, err := json.Marshal(payload)
	require.NoError(t, err)
}

func TestBuildMetricsPayload_UsesCurrentTimeWrapper(t *testing.T) {
	startup := time.Now().UTC().Add(-5 * time.Minute)
	payload := BuildMetricsPayload("1.0.0", startup, 60, 7)
	require.Len(t, payload.RemediationComponents, 1)

	c := payload.RemediationComponents[0]
	assert.Equal(t, "cs-abuseipdb-bouncer", c.Type)
	assert.Equal(t, "v1.0.0", c.Version)
	require.Len(t, c.Metrics, 1)
	assert.Equal(t, "processed", c.Metrics[0].Name)
	assert.Equal(t, int64(7), c.Metrics[0].Value)
	assert.Equal(t, int64(60), c.Meta.WindowSizeSeconds)
	assert.Equal(t, startup.Unix(), c.Meta.UtcStartupTimestamp)
	assert.GreaterOrEqual(t, c.Meta.UtcNowTimestamp, startup.Unix())
}

func TestNormalizeVersion(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"", "vdev"},
		{"2.0.1", "v2.0.1"},
		{"v2.0.1", "v2.0.1"},
		{"  3.1.0 ", "v3.1.0"},
	}

	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			assert.Equal(t, tc.want, normalizeVersion(tc.in))
		})
	}
}
