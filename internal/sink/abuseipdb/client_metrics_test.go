package abuseipdb

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/developingchet/cs-abuseipdb-bouncer/internal/metrics"
	"github.com/developingchet/cs-abuseipdb-bouncer/internal/sink"
)

func init() {
	// Isolate metrics from the default registry and from bouncer_test.go's registry.
	metrics.RegisterWith(prometheus.NewRegistry())
}

// TestReport_ContextDeadline_IncrementsTimeoutMetric proves that a hung API call
// is cancelled by the per-request context and increments the "timeout" error metric.
func TestReport_ContextDeadline_IncrementsTimeoutMetric(t *testing.T) {
	before := testutil.ToFloat64(metrics.APIErrors.WithLabelValues("timeout"))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond) // outlast the 100 ms context below
	}))
	defer func() {
		srv.CloseClientConnections()
		srv.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	c := buildClient(srv.URL, srv.URL)
	err := c.Report(ctx, &sink.Report{IP: "203.0.113.42", Scenario: "crowdsecurity/ssh-bf"})

	require.Error(t, err)
	after := testutil.ToFloat64(metrics.APIErrors.WithLabelValues("timeout"))
	assert.Equal(t, float64(1), after-before,
		"api_errors{type=timeout} must be incremented by exactly 1")
}

// TestReport_RateLimit429_IncrementsMetricAndExtractsRetryAfter verifies that a
// 429 response (a) increments the rate_limit metric and (b) extracts the Retry-After
// seconds from the JSON body.
func TestReport_RateLimit429_IncrementsMetricAndExtractsRetryAfter(t *testing.T) {
	before := testutil.ToFloat64(metrics.APIErrors.WithLabelValues("rate_limit"))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, `{"errors":[{"detail":"Try again in 1 seconds."}]}`)
	}))
	defer srv.Close()

	// Allow up to 3 s so the extracted 1-second Retry-After sleep can complete.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	c := buildClient(srv.URL, srv.URL)
	err := c.Report(ctx, &sink.Report{IP: "203.0.113.42", Scenario: "crowdsecurity/ssh-bf"})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "rate limited")

	after := testutil.ToFloat64(metrics.APIErrors.WithLabelValues("rate_limit"))
	assert.Equal(t, float64(1), after-before,
		"api_errors{type=rate_limit} must be incremented by exactly 1")
}
