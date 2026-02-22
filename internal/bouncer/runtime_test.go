package bouncer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/developingchet/cs-abuseipdb-bouncer/internal/config"
	"github.com/developingchet/cs-abuseipdb-bouncer/internal/sink"
	"github.com/developingchet/cs-abuseipdb-bouncer/internal/storage"
	"github.com/developingchet/cs-abuseipdb-bouncer/internal/telemetry"
)

type recordingSink struct {
	mu      sync.Mutex
	reports int
}

func (s *recordingSink) Name() string { return "recording" }
func (s *recordingSink) Report(_ context.Context, _ *sink.Report) error {
	s.mu.Lock()
	s.reports++
	s.mu.Unlock()
	return nil
}
func (s *recordingSink) Healthy(_ context.Context) error { return nil }
func (s *recordingSink) Close() error                    { return nil }
func (s *recordingSink) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reports
}

func baseRunConfig(t *testing.T, lapiURL string) *config.Config {
	t.Helper()
	return &config.Config{
		LAPIURL:              lapiURL,
		LAPIKey:              "test-key",
		DailyLimit:           1000,
		PollInterval:         20 * time.Millisecond,
		LAPITimeout:          10 * time.Second,
		CooldownDuration:     time.Second,
		DataDir:              t.TempDir(),
		MetricsAddr:          "",
		WorkerCount:          1,
		WorkerBuffer:         16,
		JanitorInterval:      time.Hour,
		UsageMetricsEnabled:  false,
		UsageMetricsInterval: 30 * time.Minute,
		BuildVersion:         "vtest",
	}
}

func TestNew_WiresStreamFields(t *testing.T) {
	cfg := baseRunConfig(t, "http://127.0.0.1:18080")
	cfg.BuildVersion = "1.2.3"
	cfg.LAPITLSCertPath = "/tmp/client.crt"
	cfg.LAPITLSKeyPath = "/tmp/client.key"
	cfg.LAPITLSCAPath = "/tmp/ca.crt"
	cfg.TLSSkipVerify = true

	b, err := New(cfg, []sink.Sink{&recordingSink{}})
	require.NoError(t, err)
	defer b.Close()

	assert.Equal(t, "http://127.0.0.1:18080", b.stream.APIUrl)
	assert.Equal(t, cfg.PollInterval.String(), b.stream.TickerInterval)
	assert.Equal(t, "cs-abuseipdb-bouncer/1.2.3", b.stream.UserAgent)
	assert.Equal(t, "/tmp/client.crt", b.stream.CertPath)
	assert.Equal(t, "/tmp/client.key", b.stream.KeyPath)
	assert.Equal(t, "/tmp/ca.crt", b.stream.CAPath)
	require.NotNil(t, b.stream.InsecureSkipVerify)
	assert.True(t, *b.stream.InsecureSkipVerify)
}

func TestNew_OpenError(t *testing.T) {
	cfg := baseRunConfig(t, "http://127.0.0.1:18080")
	cfg.DataDir = filepath.Join(t.TempDir(), "missing", "nested")
	_, err := New(cfg, []sink.Sink{&recordingSink{}})
	require.Error(t, err)
}

func TestNew_MetricsHandlers(t *testing.T) {
	cfg := baseRunConfig(t, "http://127.0.0.1:18080")
	cfg.MetricsAddr = "127.0.0.1:9090"

	okBouncer, err := New(cfg, []sink.Sink{&recordingSink{}})
	require.NoError(t, err)
	defer okBouncer.Close()

	healthRec := httptest.NewRecorder()
	healthReq := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	okBouncer.httpSrv.Handler.ServeHTTP(healthRec, healthReq)
	assert.Equal(t, http.StatusOK, healthRec.Code)

	readyRec := httptest.NewRecorder()
	readyReq := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	okBouncer.httpSrv.Handler.ServeHTTP(readyRec, readyReq)
	assert.Equal(t, http.StatusOK, readyRec.Code)

	badCfg := baseRunConfig(t, "http://127.0.0.1:18080")
	badCfg.MetricsAddr = "127.0.0.1:9090"
	badBouncer, err := New(badCfg, []sink.Sink{&healthErrSink{err: errors.New("upstream down")}})
	require.NoError(t, err)
	defer badBouncer.Close()
	badReadyRec := httptest.NewRecorder()
	badReadyReq := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	badBouncer.httpSrv.Handler.ServeHTTP(badReadyRec, badReadyReq)
	assert.Equal(t, http.StatusServiceUnavailable, badReadyRec.Code)
}

func TestRun_HappyPathReportsDecision(t *testing.T) {
	var streamCalls atomic.Int32
	var lastUA atomic.Value

	lapi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/decisions/stream":
			lastUA.Store(r.UserAgent())
			assert.Equal(t, "test-key", r.Header.Get("X-Api-Key"))
			w.Header().Set("Content-Type", "application/json")
			if streamCalls.Add(1) == 1 {
				fmt.Fprint(w, `{"deleted":null,"new":[{"duration":"1h","id":1,"origin":"crowdsec","scenario":"crowdsecurity/ssh-bf","scope":"ip","type":"ban","value":"203.0.113.42"}]}`)
				return
			}
			fmt.Fprint(w, `{"deleted":null,"new":null}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer lapi.Close()

	cfg := baseRunConfig(t, lapi.URL)
	cfg.LAPITimeout = 250 * time.Millisecond
	rs := &recordingSink{}
	b, err := New(cfg, []sink.Sink{rs})
	require.NoError(t, err)
	defer b.Close()

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- b.Run(ctx) }()

	require.Eventually(t, func() bool { return rs.Count() == 1 }, 3*time.Second, 20*time.Millisecond)
	cancel()
	require.NoError(t, <-errCh)

	gotUA, _ := lastUA.Load().(string)
	assert.Equal(t, "cs-abuseipdb-bouncer/vtest", gotUA)
	assert.Equal(t, 250*time.Millisecond, b.stream.APIClient.GetClient().Timeout)
	assert.Equal(t, 1, rs.Count())
}

func TestRun_DeleteOnlyDoesNotReport(t *testing.T) {
	var streamCalls atomic.Int32
	lapi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/decisions/stream" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if streamCalls.Add(1) == 1 {
			fmt.Fprint(w, `{"deleted":[{"duration":"1h","id":99,"origin":"crowdsec","scenario":"crowdsecurity/ssh-bf","scope":"ip","type":"ban","value":"203.0.113.99"}],"new":null}`)
			return
		}
		fmt.Fprint(w, `{"deleted":null,"new":null}`)
	}))
	defer lapi.Close()

	cfg := baseRunConfig(t, lapi.URL)
	rs := &recordingSink{}
	b, err := New(cfg, []sink.Sink{rs})
	require.NoError(t, err)
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	require.NoError(t, b.Run(ctx))
	assert.Equal(t, 0, rs.Count())
}

func TestRun_FiltersAndNilPayloadBranches(t *testing.T) {
	var streamCalls atomic.Int32
	lapi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/decisions/stream" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if streamCalls.Add(1) == 1 {
			fmt.Fprint(w, `{"deleted":null,"new":[null,{"duration":"1h","id":10,"origin":"crowdsec","scenario":"crowdsecurity/ssh-bf","scope":"ip","type":"ban","value":"10.0.0.9"}]}`)
			return
		}
		fmt.Fprint(w, `null`)
	}))
	defer lapi.Close()

	cfg := baseRunConfig(t, lapi.URL)
	rs := &recordingSink{}
	b, err := New(cfg, []sink.Sink{rs})
	require.NoError(t, err)
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	require.NoError(t, b.Run(ctx))
	assert.Equal(t, 0, rs.Count(), "nil and private-ip decisions should be filtered")
}

func TestRun_NilStreamDataBranch(t *testing.T) {
	var streamCalls atomic.Int32
	lapi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/decisions/stream" {
			http.NotFound(w, r)
			return
		}
		streamCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"deleted":null,"new":null}`)
	}))
	defer lapi.Close()

	cfg := baseRunConfig(t, lapi.URL)
	b, err := New(cfg, []sink.Sink{&recordingSink{}})
	require.NoError(t, err)
	defer b.Close()

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- b.Run(ctx) }()

	// Inject an explicit nil payload into the stream channel to cover the guard.
	require.Eventually(t, func() bool { return streamCalls.Load() > 0 }, time.Second, 10*time.Millisecond)
	require.NotNil(t, b.stream.Stream)
	select {
	case b.stream.Stream <- nil:
	case <-time.After(time.Second):
		t.Fatal("timed out injecting nil stream payload")
	}

	cancel()
	require.NoError(t, <-errCh)
}

func TestRun_PushesUsageMetrics(t *testing.T) {
	var streamCalls atomic.Int32
	var usageCalls atomic.Int32
	var payloadMu sync.Mutex
	var lastPayload telemetry.MetricsPayload

	lapi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/decisions/stream":
			w.Header().Set("Content-Type", "application/json")
			if streamCalls.Add(1) == 1 {
				fmt.Fprint(w, `{"deleted":null,"new":[{"duration":"1h","id":2,"origin":"crowdsec","scenario":"crowdsecurity/ssh-bf","scope":"ip","type":"ban","value":"203.0.113.43"}]}`)
				return
			}
			fmt.Fprint(w, `{"deleted":null,"new":null}`)
		case "/v1/usage-metrics":
			usageCalls.Add(1)
			defer r.Body.Close()
			var p telemetry.MetricsPayload
			require.NoError(t, json.NewDecoder(r.Body).Decode(&p))
			payloadMu.Lock()
			lastPayload = p
			payloadMu.Unlock()
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer lapi.Close()

	cfg := baseRunConfig(t, lapi.URL)
	cfg.UsageMetricsEnabled = true
	cfg.UsageMetricsInterval = 30 * time.Millisecond
	rs := &recordingSink{}
	b, err := New(cfg, []sink.Sink{rs})
	require.NoError(t, err)
	defer b.Close()

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- b.Run(ctx) }()

	require.Eventually(t, func() bool { return usageCalls.Load() > 0 }, 3*time.Second, 20*time.Millisecond)
	cancel()
	require.NoError(t, <-errCh)
	assert.GreaterOrEqual(t, rs.Count(), 1)

	payloadMu.Lock()
	defer payloadMu.Unlock()
	require.Len(t, lastPayload.RemediationComponents, 1)
	require.NotEmpty(t, lastPayload.RemediationComponents[0].Metrics)
	assert.Equal(t, "processed", lastPayload.RemediationComponents[0].Metrics[0].Name)
	assert.GreaterOrEqual(t, lastPayload.RemediationComponents[0].Metrics[0].Value, int64(1))
}

func TestRun_UsageMetricsPushError_DoesNotCrash(t *testing.T) {
	var streamCalls atomic.Int32
	var usageCalls atomic.Int32

	lapi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/decisions/stream":
			w.Header().Set("Content-Type", "application/json")
			if streamCalls.Add(1) == 1 {
				fmt.Fprint(w, `{"deleted":null,"new":[{"duration":"1h","id":3,"origin":"crowdsec","scenario":"crowdsecurity/ssh-bf","scope":"ip","type":"ban","value":"203.0.113.44"}]}`)
				return
			}
			fmt.Fprint(w, `{"deleted":null,"new":null}`)
		case "/v1/usage-metrics":
			usageCalls.Add(1)
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `{"message":"error"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer lapi.Close()

	cfg := baseRunConfig(t, lapi.URL)
	cfg.UsageMetricsEnabled = true
	cfg.UsageMetricsInterval = 200 * time.Millisecond
	rs := &recordingSink{}
	b, err := New(cfg, []sink.Sink{rs})
	require.NoError(t, err)
	defer b.Close()

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- b.Run(ctx) }()

	require.Eventually(t, func() bool { return rs.Count() == 1 }, 2*time.Second, 20*time.Millisecond)
	require.Eventually(t, func() bool { return usageCalls.Load() > 0 }, 2*time.Second, 20*time.Millisecond)

	cancel()
	require.NoError(t, <-errCh)
	assert.GreaterOrEqual(t, usageCalls.Load(), int32(1))
}

func TestPushUsageMetrics_NilAPIClient(t *testing.T) {
	b := &Bouncer{stream: &csbouncer.StreamBouncer{}}
	err := b.pushUsageMetrics(context.Background(), telemetry.MetricsPayload{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not initialized")
}

func TestPushUsageMetrics_NewRequestError(t *testing.T) {
	lapi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer lapi.Close()

	cfg := baseRunConfig(t, lapi.URL)
	b, err := New(cfg, []sink.Sink{&recordingSink{}})
	require.NoError(t, err)
	defer b.Close()
	require.NoError(t, b.stream.Init())
	b.stream.APIClient.URLPrefix = "\x00"

	err = b.pushUsageMetrics(context.Background(), telemetry.MetricsPayload{})
	require.Error(t, err)
}

func TestRun_LAPITimeout200ms_NoCrash(t *testing.T) {
	lapi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/decisions/stream" {
			time.Sleep(500 * time.Millisecond)
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"deleted":null,"new":null}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer lapi.Close()

	cfg := baseRunConfig(t, lapi.URL)
	cfg.LAPITimeout = 200 * time.Millisecond
	b, err := New(cfg, []sink.Sink{&recordingSink{}})
	require.NoError(t, err)
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := time.Now()
	err = b.Run(ctx)
	elapsed := time.Since(start)

	require.NoError(t, err)
	assert.Less(t, elapsed, time.Second)
	assert.Equal(t, 200*time.Millisecond, b.stream.APIClient.GetClient().Timeout)
}

func TestRun_InvalidMTLSCertFailsGracefully(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	require.NoError(t, osWriteFile(certPath, []byte("not-a-cert")))
	require.NoError(t, osWriteFile(keyPath, []byte("not-a-key")))

	cfg := baseRunConfig(t, "https://127.0.0.1:8443")
	cfg.LAPIKey = ""
	cfg.LAPITLSCertPath = certPath
	cfg.LAPITLSKeyPath = keyPath
	b, err := New(cfg, []sink.Sink{&recordingSink{}})
	require.NoError(t, err)
	defer b.Close()

	err = b.Run(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unable to load certificate")
}

func TestRun_MetricsAddrInUse_NoCrash(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	lapi := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/decisions/stream" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"deleted":null,"new":null}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer lapi.Close()

	cfg := baseRunConfig(t, lapi.URL)
	cfg.MetricsAddr = ln.Addr().String()
	b, err := New(cfg, []sink.Sink{&recordingSink{}})
	require.NoError(t, err)
	defer b.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	require.NoError(t, b.Run(ctx))
}

func TestProcessDecision_TelemetryAndRecordWarningsBranches(t *testing.T) {
	store := &recordErrorStore{}
	cfg := &config.Config{DailyLimit: 1000, CooldownDuration: time.Minute}
	rs := &recordingSink{}
	b := &Bouncer{
		cfg:       cfg,
		sinks:     []sink.Sink{rs},
		filters:   buildFilters(cfg, store),
		store:     store,
		telemetry: telemetry.NewCounter(),
	}

	b.processDecision(
		context.Background(),
		strPtr("203.0.113.45"),
		strPtr("crowdsec"),
		strPtr("crowdsecurity/ssh-bf"),
		strPtr("Ip"),
		strPtr("1h"),
		"add",
	)
	assert.Equal(t, 1, rs.Count())
	assert.Equal(t, int64(1), b.telemetry.Processed())
}

func TestClose_LogsWarningBranches(t *testing.T) {
	b := &Bouncer{
		httpSrv: &http.Server{},
		store:   &errorStore{},
		sinks:   []sink.Sink{&closeErrSink{}},
	}

	assert.NotPanics(t, func() { b.Close() })
}

func TestClose_ShutdownTimeoutWarningBranch(t *testing.T) {
	origTimeout := closeShutdownTimeout
	closeShutdownTimeout = 20 * time.Millisecond
	t.Cleanup(func() { closeShutdownTimeout = origTimeout })

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := &http.Server{Handler: handler}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = ln.Close() })

	// Keep one request active so shutdown hits its timeout path.
	go func() {
		_, _ = http.Get("http://" + ln.Addr().String()) //nolint:noctx
	}()
	time.Sleep(10 * time.Millisecond)

	b := &Bouncer{
		httpSrv: srv,
		store:   storage.NewMemStore(10, time.Second),
	}
	assert.NotPanics(t, func() { b.Close() })
}

func TestLAPIUserAgent(t *testing.T) {
	assert.Equal(t, "cs-abuseipdb-bouncer/dev", lapiUserAgent(""))
	assert.Equal(t, "cs-abuseipdb-bouncer/dev", lapiUserAgent("   "))
	assert.Equal(t, "cs-abuseipdb-bouncer/v1.2.3", lapiUserAgent("v1.2.3"))
	assert.Equal(t, "cs-abuseipdb-bouncer/1.2.3", lapiUserAgent("1.2.3"))
}

type errorStore struct{}

func (s *errorStore) QuotaAllow() bool                     { return true }
func (s *errorStore) QuotaCount() int                      { return 0 }
func (s *errorStore) QuotaLimit() int                      { return 1 }
func (s *errorStore) QuotaRemaining() int                  { return 1 }
func (s *errorStore) QuotaRecord() error                   { return nil }
func (s *errorStore) QuotaConsume() (bool, error)          { return true, nil }
func (s *errorStore) CooldownAllow(string) bool            { return true }
func (s *errorStore) CooldownRecord(string) error          { return nil }
func (s *errorStore) CooldownPrune() error                 { return errors.New("prune failed") }
func (s *errorStore) CooldownConsume(string) (bool, error) { return true, nil }
func (s *errorStore) DBPath() string                       { return "" }
func (s *errorStore) Close() error                         { return errors.New("close failed") }

type closeErrSink struct{}

func (s *closeErrSink) Name() string                               { return "close-error-sink" }
func (s *closeErrSink) Report(context.Context, *sink.Report) error { return nil }
func (s *closeErrSink) Healthy(context.Context) error              { return nil }
func (s *closeErrSink) Close() error                               { return errors.New("sink close failed") }

func osWriteFile(path string, b []byte) error {
	return os.WriteFile(path, b, 0o600)
}

type healthErrSink struct{ err error }

func (s *healthErrSink) Name() string                               { return "health-err" }
func (s *healthErrSink) Report(context.Context, *sink.Report) error { return nil }
func (s *healthErrSink) Healthy(context.Context) error              { return s.err }
func (s *healthErrSink) Close() error                               { return nil }

type recordErrorStore struct{}

func (s *recordErrorStore) QuotaAllow() bool                     { return true }
func (s *recordErrorStore) QuotaCount() int                      { return 0 }
func (s *recordErrorStore) QuotaLimit() int                      { return 1000 }
func (s *recordErrorStore) QuotaRemaining() int                  { return 999 }
func (s *recordErrorStore) QuotaRecord() error                   { return errors.New("quota record failed") }
func (s *recordErrorStore) QuotaConsume() (bool, error)          { return true, nil }
func (s *recordErrorStore) CooldownAllow(string) bool            { return true }
func (s *recordErrorStore) CooldownRecord(string) error          { return errors.New("cooldown record failed") }
func (s *recordErrorStore) CooldownPrune() error                 { return nil }
func (s *recordErrorStore) CooldownConsume(string) (bool, error) { return true, nil }
func (s *recordErrorStore) DBPath() string                       { return "" }
func (s *recordErrorStore) Close() error                         { return nil }
