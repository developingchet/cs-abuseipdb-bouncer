package telemetry

import (
	"runtime"
	"strings"
	"time"
)

// The types below mirror the LAPI swagger definitions used by
// POST /v1/usage-metrics (RemediationComponentsMetrics, DetailedMetrics,
// MetricsMeta, MetricsDetailItem, OSversion). LAPI rejects the body with 422
// if a required field is missing and silently drops unknown fields.

// MetricsDetailItem is a single usage metric value.
type MetricsDetailItem struct {
	Name   string            `json:"name"`
	Value  float64           `json:"value"`
	Unit   string            `json:"unit"`
	Labels map[string]string `json:"labels,omitempty"`
}

// MetricsMeta carries the window metadata for one DetailedMetrics entry.
type MetricsMeta struct {
	WindowSizeSeconds int64 `json:"window_size_seconds"`
	UtcNowTimestamp   int64 `json:"utc_now_timestamp"`
}

// DetailedMetrics groups metric items collected over one window.
type DetailedMetrics struct {
	Items []MetricsDetailItem `json:"items"`
	Meta  MetricsMeta         `json:"meta"`
}

// OSInfo identifies the runtime operating system.
type OSInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// RemediationComponent is the top-level remediation component entry.
type RemediationComponent struct {
	Type                string            `json:"type"`
	Version             string            `json:"version"`
	OS                  OSInfo            `json:"os"`
	FeatureFlags        []string          `json:"feature_flags"`
	UtcStartupTimestamp int64             `json:"utc_startup_timestamp"`
	Metrics             []DetailedMetrics `json:"metrics"`
}

// MetricsPayload is the request body sent to /v1/usage-metrics.
type MetricsPayload struct {
	RemediationComponents []RemediationComponent `json:"remediation_components"`
}

// BuildMetricsPayload constructs the payload required by LAPI /usage-metrics.
func BuildMetricsPayload(version string, startupTime time.Time, windowSeconds int64, processed int64) MetricsPayload {
	return BuildMetricsPayloadAt(version, startupTime, windowSeconds, processed, time.Now().UTC())
}

// BuildMetricsPayloadAt constructs the payload with a caller-provided "now".
func BuildMetricsPayloadAt(
	version string,
	startupTime time.Time,
	windowSeconds int64,
	processed int64,
	now time.Time,
) MetricsPayload {
	return MetricsPayload{
		RemediationComponents: []RemediationComponent{
			{
				Type:    "cs-abuseipdb-bouncer",
				Version: normalizeVersion(version),
				OS: OSInfo{
					Name:    runtime.GOOS,
					Version: runtime.GOARCH,
				},
				FeatureFlags:        []string{},
				UtcStartupTimestamp: startupTime.UTC().Unix(),
				Metrics: []DetailedMetrics{
					{
						Items: []MetricsDetailItem{
							{
								Name:  "processed",
								Value: float64(processed),
								Unit:  "request",
							},
						},
						Meta: MetricsMeta{
							WindowSizeSeconds: windowSeconds,
							UtcNowTimestamp:   now.UTC().Unix(),
						},
					},
				},
			},
		},
	}
}

func normalizeVersion(version string) string {
	v := strings.TrimSpace(version)
	if v == "" {
		return "vdev"
	}
	if strings.HasPrefix(v, "v") {
		return v
	}
	return "v" + v
}
