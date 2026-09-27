package telemetry

import (
	"encoding/json"
	"runtime"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/go-openapi/strfmt"
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
	assert.Equal(t, []string{}, c.FeatureFlags)
	assert.Equal(t, startup.Unix(), c.UtcStartupTimestamp)
	require.Len(t, c.Metrics, 1)
	assert.Equal(t, int64(1800), c.Metrics[0].Meta.WindowSizeSeconds)
	assert.Equal(t, now.Unix(), c.Metrics[0].Meta.UtcNowTimestamp)
	require.Len(t, c.Metrics[0].Items, 1)
	assert.Equal(t, "processed", c.Metrics[0].Items[0].Name)
	assert.Equal(t, float64(500), c.Metrics[0].Items[0].Value)
	assert.Equal(t, "request", c.Metrics[0].Items[0].Unit)

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
	assert.Equal(t, startup.Unix(), c.UtcStartupTimestamp)
	require.Len(t, c.Metrics, 1)
	require.Len(t, c.Metrics[0].Items, 1)
	assert.Equal(t, "processed", c.Metrics[0].Items[0].Name)
	assert.Equal(t, float64(7), c.Metrics[0].Items[0].Value)
	assert.Equal(t, int64(60), c.Metrics[0].Meta.WindowSizeSeconds)
	assert.GreaterOrEqual(t, c.Metrics[0].Meta.UtcNowTimestamp, startup.Unix())
}

// TestBuildMetricsPayload_WireShape checks the marshalled JSON against the
// LAPI swagger, not just the Go struct fields.
func TestBuildMetricsPayload_WireShape(t *testing.T) {
	startup := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := time.Date(2026, 1, 1, 0, 30, 0, 0, time.UTC)

	body, err := json.Marshal(BuildMetricsPayloadAt("2.4.0", startup, 1800, 3, now))
	require.NoError(t, err)

	// Validate with the LAPI's own generated models.
	var am models.AllMetrics
	require.NoError(t, json.Unmarshal(body, &am))
	require.NoError(t, am.Validate(strfmt.Default))
	require.Len(t, am.RemediationComponents, 1)
	require.Len(t, am.RemediationComponents[0].Metrics, 1)
	require.Len(t, am.RemediationComponents[0].Metrics[0].Items, 1)

	// Check raw keys so renamed or misplaced fields are caught even when
	// LAPI would ignore them.
	var raw struct {
		RemediationComponents []map[string]json.RawMessage `json:"remediation_components"`
	}
	require.NoError(t, json.Unmarshal(body, &raw))
	require.Len(t, raw.RemediationComponents, 1)
	comp := raw.RemediationComponents[0]
	for _, k := range []string{"type", "version", "os", "feature_flags", "utc_startup_timestamp", "metrics"} {
		assert.Contains(t, comp, k)
	}
	assert.NotContains(t, comp, "features")
	assert.NotContains(t, comp, "meta")

	var metrics []struct {
		Items []map[string]any `json:"items"`
		Meta  map[string]any   `json:"meta"`
	}
	require.NoError(t, json.Unmarshal(comp["metrics"], &metrics))
	require.Len(t, metrics, 1)
	require.Len(t, metrics[0].Items, 1)
	assert.Equal(t, "processed", metrics[0].Items[0]["name"])
	assert.Equal(t, float64(3), metrics[0].Items[0]["value"])
	meta := metrics[0].Meta
	assert.Equal(t, float64(1800), meta["window_size_seconds"])
	assert.Equal(t, float64(now.Unix()), meta["utc_now_timestamp"])
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
