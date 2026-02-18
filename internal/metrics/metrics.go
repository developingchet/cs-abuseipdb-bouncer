// Package metrics defines package-level Prometheus metric variables for the
// cs-abuseipdb-bouncer. Call Register() once at startup to expose them on the
// default registry, or RegisterWith() to use an isolated registry in tests.
package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	// DecisionsProcessed counts every decision received from CrowdSec LAPI.
	DecisionsProcessed = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "cs_abuseipdb_decisions_processed_total",
		Help: "Total decisions received from CrowdSec LAPI.",
	})

	// ReportsSent counts IP reports successfully sent to AbuseIPDB.
	ReportsSent = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "cs_abuseipdb_reports_sent_total",
		Help: "Total IP reports successfully sent to AbuseIPDB.",
	})

	// DecisionsSkipped counts decisions skipped, labelled by filter name.
	DecisionsSkipped = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "cs_abuseipdb_decisions_skipped_total",
		Help: "Decisions skipped, by filter name.",
	}, []string{"filter"})

	// APIErrors counts AbuseIPDB API errors, labelled by type.
	// Valid types: rate_limit, auth, network, timeout.
	APIErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "cs_abuseipdb_api_errors_total",
		Help: "AbuseIPDB API errors, by type (rate_limit|auth|network|timeout).",
	}, []string{"type"})

	// QuotaRemaining is a gauge of remaining daily AbuseIPDB report quota (UTC).
	QuotaRemaining = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "cs_abuseipdb_quota_remaining",
		Help: "AbuseIPDB reports remaining in today's quota (UTC).",
	})
)

// Register registers all metrics with prometheus.DefaultRegisterer.
// Call once at process startup.
func Register() {
	RegisterWith(prometheus.DefaultRegisterer)
}

// RegisterWith registers all metrics with the given registerer.
// Use an isolated prometheus.NewRegistry() in tests to avoid conflicts.
func RegisterWith(reg prometheus.Registerer) {
	reg.MustRegister(
		DecisionsProcessed,
		ReportsSent,
		DecisionsSkipped,
		APIErrors,
		QuotaRemaining,
	)
}
