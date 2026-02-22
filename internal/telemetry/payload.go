package telemetry

import (
	"runtime"
	"strings"
	"time"
)

// MetricLabel identifies optional dimensions for a metric item.
type MetricLabel struct {
	Origin          string `json:"origin,omitempty"`
	RemediationType string `json:"remediation_type,omitempty"`
}

// Metric is a single usage metric value.
type Metric struct {
	Name   string      `json:"name"`
	Value  int64       `json:"value"`
	Unit   string      `json:"unit"`
	Labels MetricLabel `json:"labels,omitempty"`
}

// OSInfo identifies the runtime operating system.
type OSInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// MetaInfo carries window and timestamp metadata for the payload.
type MetaInfo struct {
	WindowSizeSeconds   int64 `json:"window_size_seconds"`
	UtcStartupTimestamp int64 `json:"utc_startup_timestamp"`
	UtcNowTimestamp     int64 `json:"utc_now_timestamp"`
}

// RemediationComponent is the top-level remediation component entry.
type RemediationComponent struct {
	Type     string   `json:"type"`
	Version  string   `json:"version"`
	OS       OSInfo   `json:"os"`
	Features []string `json:"features"`
	Meta     MetaInfo `json:"meta"`
	Metrics  []Metric `json:"metrics"`
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
	metrics := []Metric{
		{
			Name:  "processed",
			Value: processed,
			Unit:  "request",
		},
	}

	return MetricsPayload{
		RemediationComponents: []RemediationComponent{
			{
				Type:    "cs-abuseipdb-bouncer",
				Version: normalizeVersion(version),
				OS: OSInfo{
					Name:    runtime.GOOS,
					Version: runtime.GOARCH,
				},
				Features: []string{},
				Meta: MetaInfo{
					WindowSizeSeconds:   windowSeconds,
					UtcStartupTimestamp: startupTime.UTC().Unix(),
					UtcNowTimestamp:     now.UTC().Unix(),
				},
				Metrics: metrics,
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
