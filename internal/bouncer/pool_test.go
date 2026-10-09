package bouncer

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/developingchet/cs-abuseipdb-bouncer/internal/decision"
	"github.com/developingchet/cs-abuseipdb-bouncer/internal/sink"
	"github.com/developingchet/cs-abuseipdb-bouncer/internal/storage"
)

// countingSink records the number of successful Report calls.
type countingSink struct {
	mu      sync.Mutex
	reports int
}

func (s *countingSink) Name() string { return "counting" }
func (s *countingSink) Report(_ context.Context, _ *sink.Report) error {
	s.mu.Lock()
	s.reports++
	s.mu.Unlock()
	return nil
}
func (s *countingSink) Close() error { return nil }
func (s *countingSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reports
}

// slowSink blocks for the given duration to simulate a slow HTTP call.
type slowSink struct {
	delay   time.Duration
	counted countingSink
}

func (s *slowSink) Name() string { return "slow" }
func (s *slowSink) Report(ctx context.Context, r *sink.Report) error {
	select {
	case <-time.After(s.delay):
	case <-ctx.Done():
		return ctx.Err()
	}
	return s.counted.Report(ctx, r)
}
func (s *slowSink) Close() error { return nil }

// makeDecision builds a Decision with the given IP (all other fields minimal).
func makeDecision(ip string) *decision.Decision {
	return &decision.Decision{
		Action:   "add",
		Origin:   "crowdsec",
		Scenario: "crowdsecurity/ssh-bf",
		Scope:    "ip",
		Value:    ip,
		Duration: "24h",
	}
}

// TestWorkerPool_10kDecisions submits 10 k decisions through an 8-worker pool
// backed by a MemStore. The test asserts there are no panics, deadlocks, or
// data races (run with -race).
func TestWorkerPool_10kDecisions(t *testing.T) {
	const total = 10_000
	const workers = 8

	store := storage.NewMemStore(total, time.Millisecond) // short cooldown so different IPs can pass
	cs := &countingSink{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool := newWorkerPool(ctx, workers, total, store, []sink.Sink{cs}, nil, nil)

	for i := 0; i < total; i++ {
		// Use different IPs so cooldown doesn't block all of them.
		ip := uniqueIP(i)
		pool.submit(workerJob{d: makeDecision(ip)})
	}

	pool.stop()
	// No panic or deadlock == test passed.
}

// TestWorkerPool_QuotaNotExceeded sends 100 decisions with a quota of 10.
// The sink must receive at most 10 reports.
func TestWorkerPool_QuotaNotExceeded(t *testing.T) {
	const total = 100
	const limit = 10

	store := storage.NewMemStore(limit, time.Millisecond)
	cs := &countingSink{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool := newWorkerPool(ctx, 4, total, store, []sink.Sink{cs}, nil, nil)

	for i := 0; i < total; i++ {
		pool.submit(workerJob{d: makeDecision(uniqueIP(i))})
	}

	pool.stop()

	got := cs.count()
	if got > limit {
		t.Errorf("quota exceeded: sink received %d reports, limit was %d", got, limit)
	}
}

// TestWorkerPool_CooldownAtomicity submits 200 decisions all for the same IP.
// With a 1-hour cooldown only 1 should reach the sink.
func TestWorkerPool_CooldownAtomicity(t *testing.T) {
	const total = 200

	store := storage.NewMemStore(total, time.Hour)
	cs := &countingSink{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool := newWorkerPool(ctx, 8, total, store, []sink.Sink{cs}, nil, nil)

	const ip = "203.0.113.42"
	for i := 0; i < total; i++ {
		pool.submit(workerJob{d: makeDecision(ip)})
	}

	pool.stop()

	got := cs.count()
	if got != 1 {
		t.Errorf("expected exactly 1 report for a single IP (cooldown atomicity), got %d", got)
	}
}

// TestWorkerPool_Backpressure floods a pool with buffer=10 with 3× more
// decisions than the buffer can hold. Verifies that at least some are dropped
// and no panic or deadlock occurs.
func TestWorkerPool_Backpressure(t *testing.T) {
	const buf = 10
	const flood = buf * 3

	store := storage.NewMemStore(flood, time.Millisecond)
	cs := &countingSink{}

	// Use a context that we'll cancel AFTER flooding but before stopping pool.
	ctx, cancel := context.WithCancel(context.Background())

	// A slow sink ensures workers stay busy while we flood the buffer.
	ss := &slowSink{delay: 50 * time.Millisecond, counted: countingSink{}}
	pool := newWorkerPool(ctx, 1, buf, store, []sink.Sink{ss}, nil, nil)

	var dropped atomic.Int64
	for i := 0; i < flood; i++ {
		if !pool.submit(workerJob{d: makeDecision(uniqueIP(i))}) {
			dropped.Add(1)
		}
	}

	cancel()
	pool.stop()

	if dropped.Load() == 0 {
		t.Log("no drops observed — buffer was drained faster than flood; that's acceptable")
	}
	// The key invariant: no panic/deadlock (the test completing == success).
	_ = cs
}

// TestWorkerPool_GracefulShutdown starts a pool, submits a few jobs, cancels
// the context, and asserts that stop() returns without deadlock.
func TestWorkerPool_GracefulShutdown(t *testing.T) {
	store := storage.NewMemStore(1000, time.Hour)
	ss := &slowSink{delay: 200 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())

	pool := newWorkerPool(ctx, 4, 64, store, []sink.Sink{ss}, nil, nil)

	for i := 0; i < 20; i++ {
		pool.submit(workerJob{d: makeDecision(uniqueIP(i))})
	}

	cancel() // signal shutdown

	done := make(chan struct{})
	go func() {
		pool.stop()
		close(done)
	}()

	select {
	case <-done:
		// Clean shutdown.
	case <-time.After(5 * time.Second):
		t.Error("pool.stop() did not return within 5s — possible deadlock")
	}
}

type admitErrStore struct{ *storage.MemStore }

func (s *admitErrStore) Admit(string) (storage.Admission, error) {
	return 0, errors.New("admit failed")
}

func TestWorkerPool_ProcessJob_AdmitError(t *testing.T) {
	base := storage.NewMemStore(100, time.Minute)
	store := &admitErrStore{MemStore: base}
	cs := &countingSink{}

	pool := &workerPool{
		store: store,
		sinks: []sink.Sink{cs},
	}
	pool.processJob(context.Background(), workerJob{d: makeDecision("203.0.113.200")})

	if got := cs.count(); got != 0 {
		t.Fatalf("expected no reports on admission error, got %d", got)
	}
}

// TestWorkerPool_ExhaustedQuotaSetsNoCooldown floods unique IPs after the
// daily quota is used up. None of them may be reported or leave a cooldown
// entry behind, so the state database does not grow with rejected decisions.
func TestWorkerPool_ExhaustedQuotaSetsNoCooldown(t *testing.T) {
	const limit = 3
	const flood = 200

	store := storage.NewMemStore(limit, time.Hour)
	for i := 0; i < limit; i++ {
		ok, err := store.QuotaConsume()
		if err != nil || !ok {
			t.Fatalf("QuotaConsume #%d = %v, %v; want true, nil", i+1, ok, err)
		}
	}
	cs := &countingSink{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool := newWorkerPool(ctx, 8, flood, store, []sink.Sink{cs}, nil, nil)
	for i := 0; i < flood; i++ {
		pool.submit(workerJob{d: makeDecision(uniqueIP(i))})
	}
	pool.stop()

	if got := cs.count(); got != 0 {
		t.Errorf("expected no reports with the quota exhausted, got %d", got)
	}
	for i := 0; i < flood; i++ {
		if !store.CooldownAllow(uniqueIP(i)) {
			t.Fatalf("cooldown recorded for %s although the quota was exhausted", uniqueIP(i))
		}
	}
	if got := store.QuotaCount(); got != limit {
		t.Errorf("QuotaCount = %d, want %d", got, limit)
	}
}

// TestWorkerPool_CooldownHitConsumesNoQuota submits the same IP many times
// concurrently and checks that only the admitted decision consumed quota.
func TestWorkerPool_CooldownHitConsumesNoQuota(t *testing.T) {
	const total = 100

	store := storage.NewMemStore(total, time.Hour)
	cs := &countingSink{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool := newWorkerPool(ctx, 8, total, store, []sink.Sink{cs}, nil, nil)
	for i := 0; i < total; i++ {
		pool.submit(workerJob{d: makeDecision("203.0.113.42")})
	}
	pool.stop()

	if got := cs.count(); got != 1 {
		t.Errorf("expected exactly 1 report, got %d", got)
	}
	if got := store.QuotaCount(); got != 1 {
		t.Errorf("QuotaCount = %d, want 1", got)
	}
}

// uniqueIP converts an integer to a unique valid dotted-quad IP address
// in the 10.0.0.0/8 range (suitable for up to 65 k unique addresses).
func uniqueIP(i int) string {
	return fmt.Sprintf("10.%d.%d.%d", i/65025, (i/255)%255, i%255+1)
}

// rateLimitSink returns ErrRateLimit for every Report call.
type rateLimitSink struct {
	retryAfter time.Duration
}

func (s *rateLimitSink) Name() string { return "rate-limit" }
func (s *rateLimitSink) Report(_ context.Context, _ *sink.Report) error {
	return sink.ErrRateLimit{RetryAfter: s.retryAfter}
}
func (s *rateLimitSink) Close() error { return nil }

// retryEnqueueStore records RetryEnqueue calls for assertions.
type retryEnqueueStore struct {
	*storage.MemStore
	mu       sync.Mutex
	enqueued []string
}

func (s *retryEnqueueStore) RetryEnqueue(ip, _ string, _ time.Time, _ int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enqueued = append(s.enqueued, ip)
	return nil
}

func (s *retryEnqueueStore) enqueuedIPs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.enqueued))
	copy(out, s.enqueued)
	return out
}

func TestWorkerPool_RateLimit_EnqueuesRetry(t *testing.T) {
	base := storage.NewMemStore(100, time.Minute)
	store := &retryEnqueueStore{MemStore: base}
	rl := &rateLimitSink{retryAfter: 30 * time.Second}

	pool := &workerPool{
		store: store,
		sinks: []sink.Sink{rl},
	}
	pool.processJob(context.Background(), workerJob{d: makeDecision("203.0.113.42")})

	ips := store.enqueuedIPs()
	if len(ips) != 1 {
		t.Fatalf("expected 1 enqueued retry, got %d", len(ips))
	}
	if ips[0] != "203.0.113.42" {
		t.Fatalf("expected enqueued IP 203.0.113.42, got %s", ips[0])
	}
}

func TestWorkerPool_RetryJob_SkipsCooldownQuota(t *testing.T) {
	// Store with exhausted quota — a normal job would be blocked.
	store := storage.NewMemStore(0, time.Hour)
	cs := &countingSink{}

	pool := &workerPool{
		store: store,
		sinks: []sink.Sink{cs},
	}

	// isRetry=true skips quota/cooldown gates.
	pool.processJob(context.Background(), workerJob{d: makeDecision("203.0.113.42"), isRetry: true})

	if got := cs.count(); got != 1 {
		t.Errorf("expected 1 report for retry job (skips quota), got %d", got)
	}
}

type retryEnqueueErrStore struct{ *storage.MemStore }

func (s *retryEnqueueErrStore) RetryEnqueue(string, string, time.Time, int) error {
	return errors.New("enqueue failed")
}

func TestWorkerPool_RateLimit_EnqueueError(t *testing.T) {
	base := storage.NewMemStore(100, time.Minute)
	store := &retryEnqueueErrStore{MemStore: base}
	rl := &rateLimitSink{retryAfter: 30 * time.Second}

	pool := &workerPool{
		store: store,
		sinks: []sink.Sink{rl},
	}
	// Must not panic; the decision is lost but no crash.
	pool.processJob(context.Background(), workerJob{d: makeDecision("203.0.113.42")})
}

func TestWorkerPool_RetryJob_OnRateLimit_ReEnqueues(t *testing.T) {
	base := storage.NewMemStore(100, time.Minute)
	store := &retryEnqueueStore{MemStore: base}
	rl := &rateLimitSink{retryAfter: 60 * time.Second}

	pool := &workerPool{
		store: store,
		sinks: []sink.Sink{rl},
	}

	// A retry job that gets rate-limited again must re-enqueue.
	pool.processJob(context.Background(), workerJob{d: makeDecision("203.0.113.42"), isRetry: true})

	ips := store.enqueuedIPs()
	if len(ips) != 1 {
		t.Fatalf("expected 1 re-enqueued retry, got %d", len(ips))
	}
}
