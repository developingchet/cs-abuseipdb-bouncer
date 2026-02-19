package bouncer

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/developingchet/cs-abuseipdb-bouncer/internal/config"
	"github.com/developingchet/cs-abuseipdb-bouncer/internal/decision"
	"github.com/developingchet/cs-abuseipdb-bouncer/internal/metrics"
	"github.com/developingchet/cs-abuseipdb-bouncer/internal/sink"
	"github.com/developingchet/cs-abuseipdb-bouncer/internal/storage"

	"github.com/prometheus/client_golang/prometheus"
)

func init() {
	// Register metrics with an isolated registry so tests don't conflict with
	// the default Prometheus registry or each other.
	metrics.RegisterWith(prometheus.NewRegistry())
}

// fakeSink records all Report calls and optionally returns an error.
type fakeSink struct {
	reports []*sink.Report
	err     error
}

func (f *fakeSink) Name() string { return "fake" }
func (f *fakeSink) Report(_ context.Context, r *sink.Report) error {
	if f.err != nil {
		return f.err
	}
	f.reports = append(f.reports, r)
	return nil
}
func (f *fakeSink) Healthy(_ context.Context) error { return nil }
func (f *fakeSink) Close() error                    { return nil }

// newTestBouncer creates a Bouncer wired to an in-memory store and a fakeSink.
func newTestBouncer(t *testing.T, dailyLimit int, cooldown time.Duration) (*Bouncer, *fakeSink) {
	t.Helper()

	store := storage.NewMemStore(dailyLimit, cooldown)

	cfg := &config.Config{
		DailyLimit:       dailyLimit,
		CooldownDuration: cooldown,
		MinDuration:      0,
	}

	fs := &fakeSink{}
	b := &Bouncer{
		cfg:     cfg,
		sinks:   []sink.Sink{fs},
		filters: buildFilters(cfg, store),
		store:   store,
	}
	return b, fs
}

func strPtr(s string) *string { return &s }

func TestProcessDecision_PassesValidDecision(t *testing.T) {
	b, fs := newTestBouncer(t, 1000, time.Minute)

	b.processDecision(
		context.Background(),
		strPtr("203.0.113.42"),
		strPtr("crowdsec"),
		strPtr("crowdsecurity/ssh-bf"),
		strPtr("Ip"),
		strPtr("24h"),
		"add",
	)

	require.Len(t, fs.reports, 1)
	assert.Equal(t, "203.0.113.42", fs.reports[0].IP)
	assert.Equal(t, "crowdsecurity/ssh-bf", fs.reports[0].Scenario)
}

func TestProcessDecision_FiltersDeleteAction(t *testing.T) {
	b, fs := newTestBouncer(t, 1000, time.Minute)

	b.processDecision(
		context.Background(),
		strPtr("203.0.113.42"),
		strPtr("crowdsec"),
		strPtr("crowdsecurity/ssh-bf"),
		strPtr("Ip"),
		strPtr("24h"),
		"del", // ActionFilter should reject this
	)

	assert.Empty(t, fs.reports)
}

func TestProcessDecision_FiltersPrivateIP(t *testing.T) {
	b, fs := newTestBouncer(t, 1000, time.Minute)

	b.processDecision(
		context.Background(),
		strPtr("192.168.1.1"),
		strPtr("crowdsec"),
		strPtr("crowdsecurity/ssh-bf"),
		strPtr("Ip"),
		strPtr("24h"),
		"add",
	)

	assert.Empty(t, fs.reports)
}

func TestProcessDecision_FiltersCAPIOrigin(t *testing.T) {
	b, fs := newTestBouncer(t, 1000, time.Minute)

	b.processDecision(
		context.Background(),
		strPtr("203.0.113.42"),
		strPtr("CAPI"),
		strPtr("crowdsecurity/ssh-bf"),
		strPtr("Ip"),
		strPtr("24h"),
		"add",
	)

	assert.Empty(t, fs.reports)
}

func TestProcessDecision_FiltersRangeScope(t *testing.T) {
	b, fs := newTestBouncer(t, 1000, time.Minute)

	b.processDecision(
		context.Background(),
		strPtr("203.0.113.0/24"),
		strPtr("crowdsec"),
		strPtr("crowdsecurity/ssh-bf"),
		strPtr("Range"),
		strPtr("24h"),
		"add",
	)

	assert.Empty(t, fs.reports)
}

func TestProcessDecision_FiltersImpossibleTravel(t *testing.T) {
	b, fs := newTestBouncer(t, 1000, time.Minute)

	b.processDecision(
		context.Background(),
		strPtr("203.0.113.42"),
		strPtr("crowdsec"),
		strPtr("crowdsecurity/impossible-travel"),
		strPtr("Ip"),
		strPtr("24h"),
		"add",
	)

	assert.Empty(t, fs.reports)
}

func TestProcessDecision_CooldownPreventsDuplicate(t *testing.T) {
	b, fs := newTestBouncer(t, 1000, time.Minute)

	// First report should succeed.
	b.processDecision(
		context.Background(),
		strPtr("203.0.113.42"),
		strPtr("crowdsec"),
		strPtr("crowdsecurity/ssh-bf"),
		strPtr("Ip"),
		strPtr("24h"),
		"add",
	)
	require.Len(t, fs.reports, 1)

	// Second report within cooldown window should be suppressed.
	b.processDecision(
		context.Background(),
		strPtr("203.0.113.42"),
		strPtr("crowdsec"),
		strPtr("crowdsecurity/ssh-bf"),
		strPtr("Ip"),
		strPtr("24h"),
		"add",
	)
	assert.Len(t, fs.reports, 1)
}

func TestProcessDecision_QuotaExhausted(t *testing.T) {
	b, fs := newTestBouncer(t, 1, 1*time.Second) // cooldown of 1s so IPs don't block each other

	// First report consumes the entire daily quota.
	b.processDecision(
		context.Background(),
		strPtr("203.0.113.1"),
		strPtr("crowdsec"),
		strPtr("crowdsecurity/ssh-bf"),
		strPtr("Ip"),
		strPtr("24h"),
		"add",
	)
	require.Len(t, fs.reports, 1)

	// Sleep past cooldown so IP isn't blocked by cooldown filter.
	time.Sleep(1100 * time.Millisecond)

	// Second IP should be blocked by quota filter.
	b.processDecision(
		context.Background(),
		strPtr("203.0.113.2"),
		strPtr("crowdsec"),
		strPtr("crowdsecurity/ssh-bf"),
		strPtr("Ip"),
		strPtr("24h"),
		"add",
	)
	assert.Len(t, fs.reports, 1, "quota exhausted: second report should be filtered")
}

func TestProcessDecision_SinkError_DoesNotRecordState(t *testing.T) {
	store := storage.NewMemStore(1000, time.Minute)
	cfg := &config.Config{DailyLimit: 1000, CooldownDuration: time.Minute}
	fs := &fakeSink{err: errors.New("simulated API failure")}
	b := &Bouncer{
		cfg:     cfg,
		sinks:   []sink.Sink{fs},
		filters: buildFilters(cfg, store),
		store:   store,
	}

	b.processDecision(
		context.Background(),
		strPtr("203.0.113.42"),
		strPtr("crowdsec"),
		strPtr("crowdsecurity/ssh-bf"),
		strPtr("Ip"),
		strPtr("24h"),
		"add",
	)

	// Quota and cooldown must not be recorded when the sink returned an error.
	assert.Equal(t, 0, store.QuotaCount())
	assert.True(t, store.CooldownAllow("203.0.113.42"), "cooldown should not be set after sink failure")
}

func TestProcessDecision_NilPointers(t *testing.T) {
	b, fs := newTestBouncer(t, 1000, time.Minute)

	// Should not panic on nil pointer inputs.
	assert.NotPanics(t, func() {
		b.processDecision(context.Background(), nil, nil, nil, nil, nil, "add")
	})
	assert.Empty(t, fs.reports)
}

func TestQuotaFilter(t *testing.T) {
	store := storage.NewMemStore(2, time.Minute)

	f := quotaFilter(store)
	d := &decision.Decision{Value: "203.0.113.42"}

	assert.Nil(t, f(d))
	require.NoError(t, store.QuotaRecord())

	assert.Nil(t, f(d))
	require.NoError(t, store.QuotaRecord())

	// Quota exhausted -- filter should reject.
	reason := f(d)
	require.NotNil(t, reason)
	assert.Equal(t, "quota", reason.Filter)
}

func TestCooldownFilter(t *testing.T) {
	store := storage.NewMemStore(1000, time.Minute)

	f := cooldownFilter(store)
	d := &decision.Decision{Value: "203.0.113.42"}

	// First check: no cooldown active.
	assert.Nil(t, f(d))

	// Record cooldown.
	require.NoError(t, store.CooldownRecord("203.0.113.42"))

	// Second check: cooldown active.
	reason := f(d)
	require.NotNil(t, reason)
	assert.Equal(t, "cooldown", reason.Filter)
}

func TestHealthy_AllSinksOK(t *testing.T) {
	store := storage.NewMemStore(1000, time.Minute)
	cfg := &config.Config{DailyLimit: 1000, CooldownDuration: time.Minute}
	b := &Bouncer{
		cfg:   cfg,
		sinks: []sink.Sink{&fakeSink{}, &fakeSink{}},
		store: store,
	}

	assert.NoError(t, b.Healthy(context.Background()))
}

func TestHealthy_SinkFailure(t *testing.T) {
	store := storage.NewMemStore(1000, time.Minute)
	cfg := &config.Config{DailyLimit: 1000, CooldownDuration: time.Minute}
	b := &Bouncer{
		cfg:   cfg,
		sinks: []sink.Sink{&unhealthySink{}},
		store: store,
	}

	assert.Error(t, b.Healthy(context.Background()))
}

// unhealthySink always returns an error from Healthy.
type unhealthySink struct{}

func (u *unhealthySink) Name() string                                    { return "unhealthy" }
func (u *unhealthySink) Report(_ context.Context, _ *sink.Report) error { return nil }
func (u *unhealthySink) Healthy(_ context.Context) error                 { return errors.New("sink unavailable") }
func (u *unhealthySink) Close() error                                    { return nil }

func TestBuildPreQueueFilters_Whitelist(t *testing.T) {
	validDec := func(ip string) *decision.Decision {
		return &decision.Decision{
			Action:   "add",
			Origin:   "crowdsec",
			Scenario: "crowdsecurity/ssh-bf",
			Scope:    "Ip",
			Value:    ip,
			Duration: "1h",
		}
	}

	t.Run("whitelisted IP is skipped", func(t *testing.T) {
		cfg := &config.Config{
			Whitelist: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
		}
		filters := buildPreQueueFilters(cfg)
		reason := decision.Pipeline(filters, validDec("203.0.113.42"))
		require.NotNil(t, reason)
		assert.Equal(t, "whitelist", reason.Filter)
	})

	t.Run("non-whitelisted IP passes", func(t *testing.T) {
		cfg := &config.Config{
			Whitelist: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
		}
		filters := buildPreQueueFilters(cfg)
		reason := decision.Pipeline(filters, validDec("8.8.8.8"))
		assert.Nil(t, reason)
	})

	t.Run("empty whitelist does not filter any IP", func(t *testing.T) {
		cfg := &config.Config{} // Whitelist is nil — filter not added
		filters := buildPreQueueFilters(cfg)
		reason := decision.Pipeline(filters, validDec("203.0.113.42"))
		assert.Nil(t, reason)
	})
}

func TestPtrStr(t *testing.T) {
	s := "hello"
	assert.Equal(t, "hello", ptrStr(&s))
	assert.Equal(t, "", ptrStr(nil))
}

// TestBouncer_Close_StopsMetricsServer verifies that bouncer.Close() shuts
// down the Prometheus HTTP server so no goroutine leak occurs.
func TestBouncer_Close_StopsMetricsServer(t *testing.T) {
	// Find a free ephemeral port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	_ = ln.Close() // release port so the real server can bind

	store := storage.NewMemStore(1000, time.Minute)
	cfg := &config.Config{
		DailyLimit:       1000,
		CooldownDuration: time.Minute,
		MetricsAddr:      addr,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	srv := &http.Server{Addr: addr, Handler: mux}
	b := &Bouncer{cfg: cfg, store: store, httpSrv: srv}

	go func() { _ = srv.ListenAndServe() }()

	// Wait for the server to become reachable.
	require.Eventually(t, func() bool {
		resp, err := http.Get("http://" + addr + "/healthz") //nolint:noctx
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, 2*time.Second, 10*time.Millisecond, "metrics server did not start in time")

	// Close the bouncer; this must drain and stop the HTTP server.
	b.Close()

	// The server must no longer accept new connections.
	_, err = http.Get("http://" + addr + "/healthz") //nolint:noctx
	assert.Error(t, err, "metrics server must be unreachable after Close()")
}

func TestBouncer_MetricsServer_PortInUse_DoesNotPanic(t *testing.T) {
	// Pre-occupy a random ephemeral port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	addr := ln.Addr().String()

	store := storage.NewMemStore(1000, time.Minute)
	cfg := &config.Config{
		DailyLimit:       1000,
		CooldownDuration: time.Minute,
		MetricsAddr:      addr,
	}
	srv := &http.Server{Addr: addr, Handler: http.NewServeMux()}
	b := &Bouncer{cfg: cfg, store: store, httpSrv: srv}

	errCh := make(chan error, 1)
	go func() {
		// Mirror what Run() does: goroutine exits silently on non-ErrServerClosed errors.
		if e := b.httpSrv.ListenAndServe(); e != nil && e != http.ErrServerClosed {
			errCh <- e
		}
	}()

	select {
	case listenErr := <-errCh:
		// Goroutine must exit with an error, not panic.
		require.Error(t, listenErr)
		// Main logic is unaffected: store must still be operational.
		assert.True(t, b.store.QuotaAllow(), "quota allow must survive metrics server failure")
	case <-time.After(2 * time.Second):
		t.Fatal("expected metrics server to fail immediately with EADDRINUSE")
	}
	_ = srv.Close()
}
