// Package metrics_test verifies that every Prometheus metric exported by the
// metrics package can be registered without panicking, and that each increment
// or set operation is reflected in the metric's current value.
//
// Delta comparisons (before/after) are used throughout so that tests remain
// order-independent regardless of how many other tests have touched the
// package-level counters before this file runs.
package metrics_test

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/developingchet/cs-abuseipdb-bouncer/internal/metrics"
)

// TestRegisterWith_DoesNotPanic verifies that registering all five metrics
// with a fresh, isolated registry succeeds without panicking.
func TestRegisterWith_DoesNotPanic(t *testing.T) {
	assert.NotPanics(t, func() {
		metrics.RegisterWith(prometheus.NewRegistry())
	})
}

// TestRegisterWith_PanicsOnDoubleRegistration verifies the MustRegister
// behaviour: re-registering the same metrics with the same registry panics.
func TestRegisterWith_PanicsOnDoubleRegistration(t *testing.T) {
	reg := prometheus.NewRegistry()
	metrics.RegisterWith(reg)
	assert.Panics(t, func() {
		metrics.RegisterWith(reg)
	})
}

// TestDecisionsProcessed_Increments verifies that .Inc() advances the counter
// by exactly one.
func TestDecisionsProcessed_Increments(t *testing.T) {
	before := testutil.ToFloat64(metrics.DecisionsProcessed)
	metrics.DecisionsProcessed.Inc()
	assert.Equal(t, before+1, testutil.ToFloat64(metrics.DecisionsProcessed))
}

// TestReportsSent_Increments verifies that .Inc() advances the counter by
// exactly one.
func TestReportsSent_Increments(t *testing.T) {
	before := testutil.ToFloat64(metrics.ReportsSent)
	metrics.ReportsSent.Inc()
	assert.Equal(t, before+1, testutil.ToFloat64(metrics.ReportsSent))
}

// TestDecisionsSkipped_IncrementsByFilter verifies that each filter label is
// tracked independently and incremented by exactly one.
func TestDecisionsSkipped_IncrementsByFilter(t *testing.T) {
	filters := []string{
		"action", "origin", "scope", "value", "private_ip",
		"min_duration", "quota", "cooldown",
	}
	for _, f := range filters {
		f := f
		t.Run(f, func(t *testing.T) {
			before := testutil.ToFloat64(metrics.DecisionsSkipped.WithLabelValues(f))
			metrics.DecisionsSkipped.WithLabelValues(f).Inc()
			assert.Equal(t, before+1, testutil.ToFloat64(metrics.DecisionsSkipped.WithLabelValues(f)))
		})
	}
}

// TestAPIErrors_IncrementsByType verifies that each API error type label is
// tracked independently and incremented by exactly one.
func TestAPIErrors_IncrementsByType(t *testing.T) {
	types := []string{"rate_limit", "auth", "network", "timeout"}
	for _, typ := range types {
		typ := typ
		t.Run(typ, func(t *testing.T) {
			before := testutil.ToFloat64(metrics.APIErrors.WithLabelValues(typ))
			metrics.APIErrors.WithLabelValues(typ).Inc()
			assert.Equal(t, before+1, testutil.ToFloat64(metrics.APIErrors.WithLabelValues(typ)))
		})
	}
}

// TestQuotaRemaining_SetAndDec verifies that Set establishes an exact value
// and Dec reduces it by one.
func TestQuotaRemaining_SetAndDec(t *testing.T) {
	metrics.QuotaRemaining.Set(500)
	require.Equal(t, float64(500), testutil.ToFloat64(metrics.QuotaRemaining))

	metrics.QuotaRemaining.Dec()
	assert.Equal(t, float64(499), testutil.ToFloat64(metrics.QuotaRemaining))
}
