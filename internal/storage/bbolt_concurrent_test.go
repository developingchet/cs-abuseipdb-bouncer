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

// TestAdmit_ConcurrentUniqueIPs fires 50 goroutines with unique IPs against a
// store with limit=10. Exactly 10 are admitted and only those leave a
// cooldown entry.
func TestAdmit_ConcurrentUniqueIPs(t *testing.T) {
	const goroutines = 50
	const limit = 10

	store := openTestStore(t, limit, time.Hour)

	var wg sync.WaitGroup
	var granted atomic.Int64
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			got, err := store.Admit(ip)
			if err != nil {
				t.Errorf("Admit(%s) error: %v", ip, err)
				return
			}
			if got == AdmitGranted {
				granted.Add(1)
			}
		}(fmt.Sprintf("203.0.113.%d", i+1))
	}
	wg.Wait()

	if got := granted.Load(); got != limit {
		t.Errorf("expected %d admitted, got %d", limit, got)
	}
	if got := cooldownKeyCount(t, store); got != limit {
		t.Errorf("expected %d cooldown entries, got %d", limit, got)
	}
}

// TestAdmit_ConcurrentSameIP fires 20 goroutines for the same IP. Exactly one
// is admitted and the cooldown hits consume no quota.
func TestAdmit_ConcurrentSameIP(t *testing.T) {
	const goroutines = 20

	store := openTestStore(t, 1000, time.Hour)

	var wg sync.WaitGroup
	var granted atomic.Int64
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := store.Admit("203.0.113.99")
			if err != nil {
				t.Errorf("Admit error: %v", err)
				return
			}
			if got == AdmitGranted {
				granted.Add(1)
			}
		}()
	}
	wg.Wait()

	if got := granted.Load(); got != 1 {
		t.Errorf("expected exactly 1 admitted, got %d", got)
	}
	if got := store.QuotaCount(); got != 1 {
		t.Errorf("QuotaCount = %d, want 1", got)
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
