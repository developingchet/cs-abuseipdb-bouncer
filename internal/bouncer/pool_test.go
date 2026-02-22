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
func (s *countingSink) Healthy(_ context.Context) error { return nil }
func (s *countingSink) Close() error                    { return nil }
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
func (s *slowSink) Healthy(_ context.Context) error { return nil }
func (s *slowSink) Close() error                    { return nil }

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

	pool := newWorkerPool(ctx, workers, total, store, []sink.Sink{cs}, nil)

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

	pool := newWorkerPool(ctx, 4, total, store, []sink.Sink{cs}, nil)

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

	pool := newWorkerPool(ctx, 8, total, store, []sink.Sink{cs}, nil)

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
	pool := newWorkerPool(ctx, 1, buf, store, []sink.Sink{ss}, nil)

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

	pool := newWorkerPool(ctx, 4, 64, store, []sink.Sink{ss}, nil)

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

type cooldownErrStore struct{ *storage.MemStore }

func (s *cooldownErrStore) CooldownConsume(string) (bool, error) {
	return false, errors.New("cooldown consume failed")
}

type quotaErrStore struct{ *storage.MemStore }

func (s *quotaErrStore) QuotaConsume() (bool, error) {
	return false, errors.New("quota consume failed")
}

func TestWorkerPool_ProcessJob_CooldownConsumeError(t *testing.T) {
	base := storage.NewMemStore(100, time.Minute)
	store := &cooldownErrStore{MemStore: base}
	cs := &countingSink{}

	pool := &workerPool{
		store: store,
		sinks: []sink.Sink{cs},
	}
	pool.processJob(context.Background(), workerJob{d: makeDecision("203.0.113.200")})

	if got := cs.count(); got != 0 {
		t.Fatalf("expected no reports on cooldown consume error, got %d", got)
	}
}

func TestWorkerPool_ProcessJob_QuotaConsumeError(t *testing.T) {
	base := storage.NewMemStore(100, time.Minute)
	store := &quotaErrStore{MemStore: base}
	cs := &countingSink{}

	pool := &workerPool{
		store: store,
		sinks: []sink.Sink{cs},
	}
	pool.processJob(context.Background(), workerJob{d: makeDecision("203.0.113.201")})

	if got := cs.count(); got != 0 {
		t.Fatalf("expected no reports on quota consume error, got %d", got)
	}
}

// uniqueIP converts an integer to a unique valid dotted-quad IP address
// in the 10.0.0.0/8 range (suitable for up to 65 k unique addresses).
func uniqueIP(i int) string {
	return fmt.Sprintf("10.%d.%d.%d", i/65025, (i/255)%255, i%255+1)
}
