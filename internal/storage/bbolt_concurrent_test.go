package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func openTestStore(t *testing.T, limit int, cooldown time.Duration) *BoltStore {
	t.Helper()
	dir := t.TempDir()
	store, err := Open(filepath.Join(dir, "test.db"), limit, cooldown)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// TestQuotaConsume_Concurrent fires 50 goroutines simultaneously against a
// store with limit=10. Exactly 10 should succeed.
func TestQuotaConsume_Concurrent(t *testing.T) {
	const goroutines = 50
	const limit = 10

	store := openTestStore(t, limit, time.Minute)

	var wg sync.WaitGroup
	var successes atomic.Int64

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := store.QuotaConsume()
			if err != nil {
				t.Errorf("QuotaConsume error: %v", err)
				return
			}
			if ok {
				successes.Add(1)
			}
		}()
	}

	wg.Wait()

	got := successes.Load()
	if got != limit {
		t.Errorf("expected %d successful QuotaConsume calls, got %d", limit, got)
	}
}

// TestCooldownConsume_SameIP fires 20 goroutines for the same IP against a
// store with a 1-minute cooldown. Exactly 1 should succeed.
func TestCooldownConsume_SameIP(t *testing.T) {
	const goroutines = 20
	const ip = "203.0.113.42"

	store := openTestStore(t, 1000, time.Minute)

	var wg sync.WaitGroup
	var successes atomic.Int64

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := store.CooldownConsume(ip)
			if err != nil {
				t.Errorf("CooldownConsume error: %v", err)
				return
			}
			if ok {
				successes.Add(1)
			}
		}()
	}

	wg.Wait()

	got := successes.Load()
	if got != 1 {
		t.Errorf("expected exactly 1 successful CooldownConsume for same IP, got %d", got)
	}
}

// TestCooldownConsume_DifferentIPs fires 20 goroutines each with a unique IP.
// All 20 should succeed since they have independent cooldown keys.
func TestCooldownConsume_DifferentIPs(t *testing.T) {
	const goroutines = 20

	store := openTestStore(t, 1000, time.Minute)

	var wg sync.WaitGroup
	var successes atomic.Int64

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		ip := fmt.Sprintf("203.0.113.%d", i+1)
		go func(ip string) {
			defer wg.Done()
			ok, err := store.CooldownConsume(ip)
			if err != nil {
				t.Errorf("CooldownConsume error for %s: %v", ip, err)
				return
			}
			if ok {
				successes.Add(1)
			}
		}(ip)
	}

	wg.Wait()

	got := successes.Load()
	if got != goroutines {
		t.Errorf("expected all %d CooldownConsume calls to succeed (different IPs), got %d", goroutines, got)
	}
}

// TestDBPath verifies BoltStore returns a non-empty path.
func TestDBPath(t *testing.T) {
	store := openTestStore(t, 100, time.Minute)
	path := store.DBPath()
	if path == "" {
		t.Error("expected non-empty DBPath")
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("DBPath %q does not exist: %v", path, err)
	}
}
