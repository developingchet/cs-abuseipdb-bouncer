package bouncer

import (
	"context"
	"testing"
	"time"

	"github.com/developingchet/cs-abuseipdb-bouncer/internal/config"
	"github.com/developingchet/cs-abuseipdb-bouncer/internal/decision"
	"github.com/developingchet/cs-abuseipdb-bouncer/internal/sink"
	"github.com/developingchet/cs-abuseipdb-bouncer/internal/storage"
)

// buildTestBouncer creates a minimal Bouncer for retry worker tests.
func buildTestBouncer(store storage.Store, sinks []sink.Sink) *Bouncer {
	cfg := &config.Config{
		RetryCheckInterval: 30 * time.Second,
	}
	b := &Bouncer{
		cfg:   cfg,
		store: store,
		sinks: sinks,
	}
	// pool must be initialised because flushRetryQueue calls b.pool.submit.
	ctx, cancel := context.WithCancel(context.Background())
	_ = cancel
	b.pool = newWorkerPool(ctx, 1, 64, store, sinks, nil)
	return b
}

func TestFlushRetryQueue_DrainsPastDue(t *testing.T) {
	store := storage.NewMemStore(1000, time.Minute)
	cs := &countingSink{}
	b := buildTestBouncer(store, []sink.Sink{cs})

	// Enqueue a past-due retry entry.
	past := time.Now().Add(-time.Second)
	if err := store.RetryEnqueue("203.0.113.42", "crowdsecurity/ssh-bf", past); err != nil {
		t.Fatalf("RetryEnqueue: %v", err)
	}

	b.flushRetryQueue(context.Background())
	b.pool.stop()

	if got := cs.count(); got != 1 {
		t.Errorf("expected 1 report for past-due retry entry, got %d", got)
	}

	// Entry must have been removed from the store.
	count, err := store.RetryCount()
	if err != nil {
		t.Fatalf("RetryCount: %v", err)
	}
	if count != 0 {
		t.Errorf("expected retry queue empty after flush, got %d", count)
	}
}

func TestFlushRetryQueue_IgnoresFuture(t *testing.T) {
	store := storage.NewMemStore(1000, time.Minute)
	cs := &countingSink{}
	b := buildTestBouncer(store, []sink.Sink{cs})

	// Enqueue a future entry — should not be flushed.
	future := time.Now().Add(time.Hour)
	if err := store.RetryEnqueue("203.0.113.42", "crowdsecurity/ssh-bf", future); err != nil {
		t.Fatalf("RetryEnqueue: %v", err)
	}

	b.flushRetryQueue(context.Background())
	b.pool.stop()

	if got := cs.count(); got != 0 {
		t.Errorf("expected 0 reports for future retry entry, got %d", got)
	}
}

func TestFlushRetryQueue_BufferFull_Metrics(t *testing.T) {
	// Use buffer=0 so submit always drops and we can observe the skip path.
	store := storage.NewMemStore(1000, time.Minute)
	cs := &countingSink{}

	cfg := &config.Config{RetryCheckInterval: 30 * time.Second}
	b := &Bouncer{cfg: cfg, store: store, sinks: []sink.Sink{cs}}

	// Build a pool with zero-length buffer so every submit fails.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b.pool = newWorkerPool(ctx, 1, 1, store, []sink.Sink{cs}, nil)

	past := time.Now().Add(-time.Second)
	if err := store.RetryEnqueue("203.0.113.42", "crowdsecurity/ssh-bf", past); err != nil {
		t.Fatalf("RetryEnqueue: %v", err)
	}

	// Flood the single-slot buffer so submit will fail.
	slowD := &decision.Decision{Action: "add", Origin: "crowdsec", Scenario: "s", Scope: "ip", Value: "10.0.0.1"}
	for i := 0; i < 10; i++ {
		b.pool.submit(workerJob{d: slowD})
	}

	// flushRetryQueue must not panic and must delete the entry regardless.
	b.flushRetryQueue(context.Background())
	// The entry was deleted before submit attempt.
	count, err := store.RetryCount()
	if err != nil {
		t.Fatalf("RetryCount: %v", err)
	}
	if count != 0 {
		t.Errorf("expected retry entry deleted even when buffer full, got count=%d", count)
	}
}

func TestRunRetryWorker_DrainOnStartup(t *testing.T) {
	store := storage.NewMemStore(1000, time.Minute)
	cs := &countingSink{}

	cfg := &config.Config{RetryCheckInterval: time.Hour} // long interval, relies only on startup drain
	b := &Bouncer{cfg: cfg, store: store, sinks: []sink.Sink{cs}}

	ctx, cancel := context.WithCancel(context.Background())
	b.pool = newWorkerPool(ctx, 1, 64, store, []sink.Sink{cs}, nil)

	past := time.Now().Add(-time.Second)
	if err := store.RetryEnqueue("203.0.113.42", "crowdsecurity/ssh-bf", past); err != nil {
		t.Fatalf("RetryEnqueue: %v", err)
	}

	workerDone := make(chan struct{})
	go func() {
		b.runRetryWorker(ctx)
		close(workerDone)
	}()

	// Give the startup drain a moment to execute.
	time.Sleep(50 * time.Millisecond)
	cancel()
	b.pool.stop()
	<-workerDone

	if got := cs.count(); got != 1 {
		t.Errorf("expected 1 report from startup drain, got %d", got)
	}
}
