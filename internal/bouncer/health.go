package bouncer

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/developingchet/cs-abuseipdb-bouncer/internal/metrics"
)

const (
	// A LAPI pull is considered stale after this many poll intervals…
	healthStalePollMultiplier = 5
	// …but never sooner than this, so short poll intervals plus a slow LAPI
	// response do not flap the health status.
	minHealthStaleAfter = 2 * time.Minute
	// Consecutive failed AbuseIPDB calls (network errors, 5xx, 401) after which
	// the process reports unhealthy. Rate limits and duplicates do not count:
	// they prove the API is reachable and the key is accepted.
	maxConsecutiveSinkFailures = 5
)

// healthState records liveness signals from the running process so that
// /healthz and /readyz can answer from memory, without touching state.db or
// spending AbuseIPDB quota. All methods are safe for concurrent use and on a
// nil receiver (tests that build pools without health tracking).
type healthState struct {
	now        func() time.Time
	startedAt  time.Time
	staleAfter time.Duration

	lastLAPIPull    atomic.Int64 // unix nanos; 0 = never
	lastSinkOK      atomic.Int64 // unix nanos; 0 = never
	lastSinkFailure atomic.Int64 // unix nanos; 0 = never
	sinkFailures    atomic.Int64 // consecutive failures since the last OK
}

func newHealthState(pollInterval time.Duration, now func() time.Time) *healthState {
	return &healthState{
		now:        now,
		startedAt:  now(),
		staleAfter: max(minHealthStaleAfter, healthStalePollMultiplier*pollInterval),
	}
}

// recordLAPIPull marks a successful decision-stream poll.
func (h *healthState) recordLAPIPull() {
	if h == nil {
		return
	}
	t := h.now()
	h.lastLAPIPull.Store(t.UnixNano())
	metrics.LastLAPIPull.Set(float64(t.Unix()))
}

// recordSinkOK marks an AbuseIPDB call that reached the API with valid
// credentials, whatever the per-report outcome.
func (h *healthState) recordSinkOK() {
	if h == nil {
		return
	}
	h.lastSinkOK.Store(h.now().UnixNano())
	h.sinkFailures.Store(0)
}

// recordSinkFailure marks an AbuseIPDB call that failed in a way that points
// at connectivity or credentials.
func (h *healthState) recordSinkFailure() {
	if h == nil {
		return
	}
	h.lastSinkFailure.Store(h.now().UnixNano())
	h.sinkFailures.Add(1)
}

// healthReport is the JSON body served by /healthz and /readyz.
type healthReport struct {
	Status                       string `json:"status"`
	Reason                       string `json:"reason,omitempty"`
	LastLAPIPull                 string `json:"last_lapi_pull,omitempty"`
	LastAbuseIPDBOK              string `json:"last_abuseipdb_ok,omitempty"`
	LastAbuseIPDBFailure         string `json:"last_abuseipdb_failure,omitempty"`
	ConsecutiveAbuseIPDBFailures int64  `json:"consecutive_abuseipdb_failures"`
}

// live reports whether the process is doing its job: the LAPI has been
// polled recently and AbuseIPDB calls are not failing repeatedly. During the
// first staleAfter after startup a missing LAPI pull is tolerated.
func (h *healthState) live() (healthReport, error) {
	now := h.now()
	r := h.report()

	var err error
	switch pull := h.lastLAPIPull.Load(); {
	case pull == 0 && now.Sub(h.startedAt) > h.staleAfter:
		err = fmt.Errorf("no successful LAPI pull since startup %s ago", now.Sub(h.startedAt).Round(time.Second))
	case pull != 0 && now.Sub(time.Unix(0, pull)) > h.staleAfter:
		err = fmt.Errorf("last successful LAPI pull was %s ago", now.Sub(time.Unix(0, pull)).Round(time.Second))
	case r.ConsecutiveAbuseIPDBFailures >= maxConsecutiveSinkFailures:
		err = fmt.Errorf("last %d AbuseIPDB calls failed", r.ConsecutiveAbuseIPDBFailures)
	}
	return withStatus(r, err)
}

// ready additionally requires at least one successful LAPI pull.
func (h *healthState) ready() (healthReport, error) {
	r, err := h.live()
	if err == nil && h.lastLAPIPull.Load() == 0 {
		return withStatus(r, fmt.Errorf("waiting for first LAPI pull"))
	}
	return r, err
}

func (h *healthState) report() healthReport {
	return healthReport{
		LastLAPIPull:                 formatNanos(h.lastLAPIPull.Load()),
		LastAbuseIPDBOK:              formatNanos(h.lastSinkOK.Load()),
		LastAbuseIPDBFailure:         formatNanos(h.lastSinkFailure.Load()),
		ConsecutiveAbuseIPDBFailures: h.sinkFailures.Load(),
	}
}

func withStatus(r healthReport, err error) (healthReport, error) {
	if err != nil {
		r.Status = "unhealthy"
		r.Reason = err.Error()
		return r, err
	}
	r.Status = "ok"
	r.Reason = ""
	return r, nil
}

func formatNanos(n int64) string {
	if n == 0 {
		return ""
	}
	return time.Unix(0, n).UTC().Format(time.RFC3339)
}

// healthHandler serves a healthReport as JSON: 200 when check passes, 503
// otherwise.
func healthHandler(check func() (healthReport, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		r, err := check()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		if encErr := json.NewEncoder(w).Encode(r); encErr != nil {
			log.Debug().Err(encErr).Msg("health response write failed")
		}
	}
}
