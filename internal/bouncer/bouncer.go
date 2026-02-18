// Package bouncer implements the main event loop that connects the CrowdSec
// LAPI to the AbuseIPDB sink via a typed decision filter pipeline.
package bouncer

import (
	"context"
	"net/http"
	"path/filepath"
	"time"

	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"

	"github.com/developingchet/cs-abuseipdb-bouncer/internal/config"
	"github.com/developingchet/cs-abuseipdb-bouncer/internal/decision"
	"github.com/developingchet/cs-abuseipdb-bouncer/internal/metrics"
	"github.com/developingchet/cs-abuseipdb-bouncer/internal/sink"
	"github.com/developingchet/cs-abuseipdb-bouncer/internal/storage"
)

const pruneEvery = 200 // Prune cooldown entries every N processed decisions.

// Bouncer connects the CrowdSec LAPI to one or more sinks.
type Bouncer struct {
	cfg     *config.Config
	sinks   []sink.Sink
	filters []decision.Filter
	store   storage.Store     // replaces *state.Quota + *state.Cooldown
	stream  *csbouncer.StreamBouncer
	httpSrv *http.Server      // nil when MetricsAddr == ""
}

// New creates a Bouncer and initialises all dependencies.
func New(cfg *config.Config, sinks []sink.Sink) (*Bouncer, error) {
	dbPath := filepath.Join(cfg.DataDir, "state.db")
	store, err := storage.Open(dbPath, cfg.DailyLimit, cfg.CooldownDuration)
	if err != nil {
		return nil, err
	}

	filters := buildFilters(cfg, store)

	tlsSkipVerify := cfg.TLSSkipVerify
	stream := &csbouncer.StreamBouncer{
		APIKey:             cfg.LAPIKey,
		APIUrl:             cfg.LAPIURL,
		TickerInterval:     cfg.PollInterval.String(),
		UserAgent:          "cs-abuseipdb-bouncer/2.0",
		InsecureSkipVerify: &tlsSkipVerify,
	}

	b := &Bouncer{
		cfg:    cfg,
		sinks:  sinks,
		filters: filters,
		store:  store,
		stream: stream,
	}

	if cfg.MetricsAddr != "" {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		})
		mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
			if err := b.Healthy(r.Context()); err != nil {
				http.Error(w, err.Error(), http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		})
		b.httpSrv = &http.Server{
			Addr:         cfg.MetricsAddr,
			Handler:      mux,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 10 * time.Second,
			IdleTimeout:  30 * time.Second,
		}
	}

	return b, nil
}

// buildFilters constructs the ordered filter pipeline.
func buildFilters(cfg *config.Config, store storage.Store) []decision.Filter {
	return []decision.Filter{
		decision.ActionFilter("add"),
		decision.ScenarioExclude("impossible-travel", "impossible_travel"),
		decision.OriginAllow("crowdsec", "cscli"),
		decision.ScopeAllow("ip"),
		decision.ValueRequired(),
		decision.PrivateIPReject(),
		decision.MinDurationFilter(cfg.MinDuration),
		quotaFilter(store),
		cooldownFilter(store),
	}
}

// quotaFilter returns a Filter that rejects decisions when the daily quota
// is exhausted.
func quotaFilter(store storage.Store) decision.Filter {
	return func(d *decision.Decision) *decision.SkipReason {
		if !store.QuotaAllow() {
			return &decision.SkipReason{Filter: "quota", Detail: "daily limit reached"}
		}
		return nil
	}
}

// cooldownFilter returns a Filter that rejects decisions for IPs that were
// reported within the cooldown window.
func cooldownFilter(store storage.Store) decision.Filter {
	return func(d *decision.Decision) *decision.SkipReason {
		if !store.CooldownAllow(d.Value) {
			return &decision.SkipReason{Filter: "cooldown", Detail: "reported recently"}
		}
		return nil
	}
}

// Run starts the LAPI stream and processes decisions until ctx is cancelled.
func (b *Bouncer) Run(ctx context.Context) error {
	if err := b.stream.Init(); err != nil {
		return err
	}

	// Start metrics / health HTTP server.
	if b.httpSrv != nil {
		go func() {
			log.Info().Str("addr", b.cfg.MetricsAddr).Msg("metrics server listening")
			if err := b.httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Error().Err(err).Msg("metrics server error")
			}
		}()
	}

	// Publish initial quota reading.
	metrics.QuotaRemaining.Set(float64(b.store.QuotaRemaining()))

	log.Info().
		Int("limit", b.cfg.DailyLimit).
		Int("used_today", b.store.QuotaCount()).
		Str("cooldown", b.cfg.CooldownDuration.String()).
		Bool("precheck", b.cfg.Precheck).
		Str("min_duration", b.cfg.MinDuration.String()).
		Str("log_level", b.cfg.LogLevel).
		Msg("bouncer started")

	go b.stream.Run(ctx)

	processed := 0
	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("bouncer stopped")
			return nil

		case data, ok := <-b.stream.Stream:
			if !ok {
				log.Info().Msg("lapi stream closed")
				return nil
			}
			if data == nil {
				continue
			}

			for _, d := range data.New {
				if d == nil {
					continue
				}
				b.processDecision(ctx, d.Value, d.Origin, d.Scenario, d.Scope, d.Duration, "add")
				processed++
				if processed%pruneEvery == 0 {
					if err := b.store.CooldownPrune(); err != nil {
						log.Warn().Err(err).Msg("cooldown prune failed")
					}
				}
			}

			for _, d := range data.Deleted {
				if d != nil && d.Value != nil {
					log.Debug().Str("ip", ptrStr(d.Value)).Msg("delete decision (no action required)")
				}
			}
		}
	}
}

// Healthy checks that all configured sinks can reach their upstream services.
func (b *Bouncer) Healthy(ctx context.Context) error {
	for _, s := range b.sinks {
		if err := s.Healthy(ctx); err != nil {
			return err
		}
	}
	return nil
}

// Close performs graceful shutdown.
func (b *Bouncer) Close() {
	if b.httpSrv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := b.httpSrv.Shutdown(ctx); err != nil {
			log.Warn().Err(err).Msg("metrics server shutdown error")
		}
	}
	if err := b.store.CooldownPrune(); err != nil {
		log.Warn().Err(err).Msg("final cooldown prune failed")
	}
	if err := b.store.Close(); err != nil {
		log.Warn().Err(err).Msg("store close failed")
	}
	for _, s := range b.sinks {
		if err := s.Close(); err != nil {
			log.Warn().Err(err).Str("sink", s.Name()).Msg("sink close failed")
		}
	}
}

// processDecision runs a single decision through the filter pipeline and,
// if it passes, reports it to all configured sinks.
func (b *Bouncer) processDecision(
	ctx context.Context,
	value, origin, scenario, scope, duration *string,
	action string,
) {
	d := &decision.Decision{
		Action:   action,
		Origin:   ptrStr(origin),
		Scenario: ptrStr(scenario),
		Scope:    ptrStr(scope),
		Value:    ptrStr(value),
		Duration: ptrStr(duration),
	}

	metrics.DecisionsProcessed.Inc()

	log.Debug().
		Str("ip", d.Value).
		Str("origin", d.Origin).
		Str("scenario", d.Scenario).
		Str("scope", d.Scope).
		Str("action", d.Action).
		Msg("decision received")

	reason := decision.Pipeline(b.filters, d)
	if reason != nil {
		metrics.DecisionsSkipped.WithLabelValues(reason.Filter).Inc()
		log.Debug().
			Str("ip", d.Value).
			Str("filter", reason.Filter).
			Str("detail", reason.Detail).
			Msg("decision filtered")
		return
	}

	r := &sink.Report{
		IP:       d.Value,
		Scenario: d.Scenario,
	}

	reported := false
	for _, s := range b.sinks {
		if err := s.Report(ctx, r); err != nil {
			log.Error().Err(err).Str("sink", s.Name()).Str("ip", d.Value).Msg("report failed")
			continue
		}
		log.Info().Str("ip", d.Value).Str("sink", s.Name()).Msg("reported")
		reported = true
	}

	if reported {
		metrics.ReportsSent.Inc()
		if err := b.store.CooldownRecord(d.Value); err != nil {
			log.Warn().Err(err).Str("ip", d.Value).Msg("failed to record cooldown")
		}
		if err := b.store.QuotaRecord(); err != nil {
			log.Warn().Err(err).Msg("failed to record quota")
		}
		metrics.QuotaRemaining.Set(float64(b.store.QuotaRemaining()))
		log.Info().
			Int("daily", b.store.QuotaCount()).
			Int("limit", b.store.QuotaLimit()).
			Msg("quota updated")
	}
}

// ptrStr safely dereferences a *string, returning "" for nil pointers.
func ptrStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
