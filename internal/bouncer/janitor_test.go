package bouncer

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/developingchet/cs-abuseipdb-bouncer/internal/metrics"
	"github.com/developingchet/cs-abuseipdb-bouncer/internal/storage"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func openJanitorStore(t *testing.T, limit int, cooldown time.Duration) *storage.BoltStore {
	t.Helper()
	store, err := storage.Open(filepath.Join(t.TempDir(), "state.db"), limit, cooldown)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// startJanitor starts runJanitor in a goroutine and returns a channel that
// receives when the goroutine has exited. Callers must cancel ctx and then
// drain the returned channel to avoid goroutine leaks across tests.
func startJanitor(ctx context.Context, store *storage.BoltStore, interval time.Duration) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		runJanitor(ctx, store, interval)
		close(done)
	}()
	return done
}

// TestJanitor_PrunesExpiredEntries inserts 1000 cooldown entries with a
// sub-millisecond cooldown (already expired), then verifies the janitor
// removes them so subsequent CooldownAllow checks return true.
func TestJanitor_PrunesExpiredEntries(t *testing.T) {
	store := openJanitorStore(t, 10000, time.Nanosecond)

	const n = 1000
	for i := 0; i < n; i++ {
		ip := fmt.Sprintf("10.0.%d.%d", i/256, i%256)
		if err := store.CooldownRecord(ip); err != nil {
			t.Fatalf("CooldownRecord %s: %v", ip, err)
		}
	}

	// Wait for entries to expire.
	time.Sleep(10 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	done := startJanitor(ctx, store, 20*time.Millisecond)

	// Give the janitor at least one tick.
	time.Sleep(60 * time.Millisecond)
	cancel()
	<-done // wait for goroutine to fully exit before checking state

	for i := 0; i < n; i++ {
		ip := fmt.Sprintf("10.0.%d.%d", i/256, i%256)
		if !store.CooldownAllow(ip) {
			t.Errorf("expected cooldown to allow %s after pruning", ip)
			break
		}
	}
}

// TestJanitor_StopsOnContextCancel verifies that a janitor with a 1-hour
// interval exits within 1 second when its context is cancelled.
func TestJanitor_StopsOnContextCancel(t *testing.T) {
	store := openJanitorStore(t, 1000, time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	done := startJanitor(ctx, store, time.Hour)

	cancel()

	select {
	case <-done:
		// Stopped promptly.
	case <-time.After(time.Second):
		t.Error("janitor did not stop within 1s of context cancellation")
	}
}

// TestJanitor_DBSizeMetric verifies that the BboltDBSizeBytes gauge is set to
// a positive value after the janitor fires once on a real BoltStore.
func TestJanitor_DBSizeMetric(t *testing.T) {
	store := openJanitorStore(t, 1000, time.Minute)

	ctx, cancel := context.WithCancel(context.Background())
	done := startJanitor(ctx, store, 20*time.Millisecond)

	// Wait for at least one tick.
	time.Sleep(60 * time.Millisecond)
	cancel()
	<-done // wait for goroutine to exit before reading metric

	// The janitor calls metrics.BboltDBSizeBytes.Set(float64(info.Size()))
	// for any store with a non-empty DBPath. The bbolt file is always > 0 bytes.
	got := testutil.ToFloat64(metrics.BboltDBSizeBytes)
	if got <= 0 {
		t.Errorf("expected BboltDBSizeBytes > 0 after janitor tick, got %v", got)
	}
}

type janitorErrorStore struct{}

func (s *janitorErrorStore) QuotaAllow() bool                     { return true }
func (s *janitorErrorStore) QuotaCount() int                      { return 0 }
func (s *janitorErrorStore) QuotaLimit() int                      { return 1 }
func (s *janitorErrorStore) QuotaRemaining() int                  { return 1 }
func (s *janitorErrorStore) QuotaRecord() error                   { return nil }
func (s *janitorErrorStore) QuotaConsume() (bool, error)          { return true, nil }
func (s *janitorErrorStore) CooldownAllow(string) bool            { return true }
func (s *janitorErrorStore) CooldownRecord(string) error          { return nil }
func (s *janitorErrorStore) CooldownPrune() error                 { return errors.New("prune failed") }
func (s *janitorErrorStore) CooldownConsume(string) (bool, error) { return true, nil }
func (s *janitorErrorStore) DBPath() string                       { return "" }
func (s *janitorErrorStore) Close() error                         { return nil }

func TestJanitor_PruneErrorBranch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runJanitor(ctx, &janitorErrorStore{}, 10*time.Millisecond)
		close(done)
	}()

	time.Sleep(25 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("janitor did not stop")
	}
}
