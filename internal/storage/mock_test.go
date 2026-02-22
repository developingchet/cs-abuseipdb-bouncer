package storage

import (
	"testing"
	"time"
)

func TestMemStore_QuotaAndCooldown(t *testing.T) {
	m := NewMemStore(2, 2*time.Second)

	if !m.QuotaAllow() {
		t.Fatal("expected quota allow on empty store")
	}
	if got := m.QuotaCount(); got != 0 {
		t.Fatalf("QuotaCount got=%d want=0", got)
	}
	if got := m.QuotaLimit(); got != 2 {
		t.Fatalf("QuotaLimit got=%d want=2", got)
	}
	if got := m.QuotaRemaining(); got != 2 {
		t.Fatalf("QuotaRemaining got=%d want=2", got)
	}

	if err := m.QuotaRecord(); err != nil {
		t.Fatalf("QuotaRecord: %v", err)
	}
	if err := m.QuotaRecord(); err != nil {
		t.Fatalf("QuotaRecord: %v", err)
	}
	if m.QuotaAllow() {
		t.Fatal("expected quota exhausted after two records")
	}
	if got := m.QuotaRemaining(); got != 0 {
		t.Fatalf("QuotaRemaining got=%d want=0", got)
	}

	allowed, err := m.QuotaConsume()
	if err != nil {
		t.Fatalf("QuotaConsume: %v", err)
	}
	if allowed {
		t.Fatal("QuotaConsume should be false when exhausted")
	}

	if !m.CooldownAllow("203.0.113.42") {
		t.Fatal("expected cooldown allow for first sighting")
	}
	if err := m.CooldownRecord("203.0.113.42"); err != nil {
		t.Fatalf("CooldownRecord: %v", err)
	}
	if m.CooldownAllow("203.0.113.42") {
		t.Fatal("expected cooldown deny immediately after record")
	}

	expired := NewMemStore(2, -time.Second)
	if err := expired.CooldownRecord("203.0.113.43"); err != nil {
		t.Fatalf("CooldownRecord expired: %v", err)
	}
	if !expired.CooldownAllow("203.0.113.43") {
		t.Fatal("expected cooldown allow for already-expired entry")
	}

	if err := m.CooldownPrune(); err != nil {
		t.Fatalf("CooldownPrune: %v", err)
	}

	if got := m.DBPath(); got != "" {
		t.Fatalf("DBPath got=%q want empty", got)
	}
	if err := m.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestMemStore_ConsumeMethods(t *testing.T) {
	m := NewMemStore(3, time.Hour)

	ok, err := m.QuotaConsume()
	if err != nil {
		t.Fatalf("QuotaConsume #1: %v", err)
	}
	if !ok {
		t.Fatal("QuotaConsume #1 should succeed")
	}
	ok, err = m.QuotaConsume()
	if err != nil {
		t.Fatalf("QuotaConsume #2: %v", err)
	}
	if !ok {
		t.Fatal("QuotaConsume #2 should succeed")
	}
	ok, err = m.QuotaConsume()
	if err != nil {
		t.Fatalf("QuotaConsume #3: %v", err)
	}
	if !ok {
		t.Fatal("QuotaConsume #3 should succeed")
	}
	ok, err = m.QuotaConsume()
	if err != nil {
		t.Fatalf("QuotaConsume #4: %v", err)
	}
	if ok {
		t.Fatal("QuotaConsume #4 should fail at limit")
	}

	coolOk, err := m.CooldownConsume("203.0.113.42")
	if err != nil {
		t.Fatalf("CooldownConsume #1: %v", err)
	}
	if !coolOk {
		t.Fatal("CooldownConsume #1 should succeed")
	}
	coolOk, err = m.CooldownConsume("203.0.113.42")
	if err != nil {
		t.Fatalf("CooldownConsume #2: %v", err)
	}
	if coolOk {
		t.Fatal("CooldownConsume #2 should fail while active")
	}
}

func TestMemStore_RefreshDateResetsQuota(t *testing.T) {
	m := NewMemStore(10, time.Minute)
	if err := m.QuotaRecord(); err != nil {
		t.Fatalf("QuotaRecord: %v", err)
	}
	m.mu.Lock()
	m.quotaDate = "2000-01-01"
	m.mu.Unlock()

	if got := m.QuotaCount(); got != 0 {
		t.Fatalf("QuotaCount after day rollover got=%d want=0", got)
	}
}

func TestMemStore_QuotaRemaining_ClampsNegative(t *testing.T) {
	m := NewMemStore(1, time.Minute)
	m.mu.Lock()
	m.quotaCount = 3
	m.mu.Unlock()

	if got := m.QuotaRemaining(); got != 0 {
		t.Fatalf("QuotaRemaining got=%d want=0", got)
	}
}

func TestMemStore_CooldownPrune_DeletesExpiredEntries(t *testing.T) {
	m := NewMemStore(10, time.Minute)
	m.mu.Lock()
	m.cooldowns[sanitizeIP("203.0.113.77")] = time.Now().Add(-time.Second).Unix()
	m.mu.Unlock()

	if err := m.CooldownPrune(); err != nil {
		t.Fatalf("CooldownPrune: %v", err)
	}
	if !m.CooldownAllow("203.0.113.77") {
		t.Fatal("expected expired entry to be deleted by prune")
	}
}
