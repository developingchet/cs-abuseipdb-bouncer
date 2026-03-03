package bouncer

import (
	"context"
	"errors"
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

// dequeueErrStore returns an error from RetryDequeue so we can exercise the
// error branch in flushRetryQueue.
type dequeueErrStore struct{ *storage.MemStore }

func (s *dequeueErrStore) RetryDequeue(time.Time, int) ([]storage.RetryRecord, error) {
	return nil, errors.New("dequeue failed")
}

// retryCountErrStore returns an error from RetryCount.
type retryCountErrStore struct{ *storage.MemStore }

func (s *retryCountErrStore) RetryCount() (int, error) {
	return 0, errors.New("count failed")
}

// retryDeleteErrStore returns an error from RetryDelete.
type retryDeleteErrStore struct{ *storage.MemStore }

func (s *retryDeleteErrStore) RetryDelete(string) error {
	return errors.New("delete failed")
}

func TestFlushRetryQueue_DequeueError(t *testing.T) {
	base := storage.NewMemStore(1000, time.Minute)

	// Seed a past-due entry so RetryCount > 0 and the dequeue path is reached.
	past := time.Now().Add(-time.Second)
	if err := base.RetryEnqueue("203.0.113.42", "crowdsecurity/ssh-bf", past); err != nil {
		t.Fatalf("RetryEnqueue: %v", err)
	}

	store := &dequeueErrStore{MemStore: base}
	cs := &countingSink{}
	b := buildTestBouncer(store, []sink.Sink{cs})

	// Must not panic even when dequeue returns an error.
	b.flushRetryQueue(context.Background())
	b.pool.stop()

	if got := cs.count(); got != 0 {
		t.Errorf("expected 0 reports when dequeue fails, got %d", got)
	}
}

func TestRunRetryWorker_TickerFires(t *testing.T) {
	store := storage.NewMemStore(1000, time.Minute)
	cs := &countingSink{}

	cfg := &config.Config{RetryCheckInterval: 20 * time.Millisecond}
	b := &Bouncer{cfg: cfg, store: store, sinks: []sink.Sink{cs}}

	ctx, cancel := context.WithCancel(context.Background())
	b.pool = newWorkerPool(ctx, 1, 64, store, []sink.Sink{cs}, nil)

	// Enqueue a past-due entry so a tick actually does something observable.
	past := time.Now().Add(-time.Second)
	if err := store.RetryEnqueue("203.0.113.42", "crowdsecurity/ssh-bf", past); err != nil {
		t.Fatalf("RetryEnqueue: %v", err)
	}

	workerDone := make(chan struct{})
	go func() {
		b.runRetryWorker(ctx)
		close(workerDone)
	}()

	// Wait long enough for at least one ticker interval.
	time.Sleep(60 * time.Millisecond)
	cancel()
	b.pool.stop()
	<-workerDone
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

func TestFlushRetryQueue_CountError(t *testing.T) {
	base := storage.NewMemStore(1000, time.Minute)
	store := &retryCountErrStore{MemStore: base}
	cs := &countingSink{}
	b := buildTestBouncer(store, []sink.Sink{cs})

	// Must not panic when RetryCount returns an error.
	b.flushRetryQueue(context.Background())
	b.pool.stop()

	if got := cs.count(); got != 0 {
		t.Errorf("expected 0 reports when RetryCount fails, got %d", got)
	}
}

func TestFlushRetryQueue_EmptyQueue(t *testing.T) {
	store := storage.NewMemStore(1000, time.Minute)
	cs := &countingSink{}
	b := buildTestBouncer(store, []sink.Sink{cs})

	// Empty store — count == 0 branch must return early without panic.
	b.flushRetryQueue(context.Background())
	b.pool.stop()

	if got := cs.count(); got != 0 {
		t.Errorf("expected 0 reports for empty retry queue, got %d", got)
	}
}

func TestFlushRetryQueue_DeleteError(t *testing.T) {
	base := storage.NewMemStore(1000, time.Minute)

	past := time.Now().Add(-time.Second)
	if err := base.RetryEnqueue("203.0.113.42", "crowdsecurity/ssh-bf", past); err != nil {
		t.Fatalf("RetryEnqueue: %v", err)
	}

	store := &retryDeleteErrStore{MemStore: base}
	cs := &countingSink{}
	b := buildTestBouncer(store, []sink.Sink{cs})

	// Must not panic when RetryDelete fails; entry is skipped, no report.
	b.flushRetryQueue(context.Background())
	b.pool.stop()

	if got := cs.count(); got != 0 {
		t.Errorf("expected 0 reports when RetryDelete fails, got %d", got)
	}
}
