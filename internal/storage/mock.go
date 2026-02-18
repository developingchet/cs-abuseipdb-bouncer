package storage

import (
	"sync"
	"time"
)

// MemStore is an in-memory implementation of Store for use in unit tests.
// It is exported so that bouncer_test.go can import it without creating a
// file on disk.
type MemStore struct {
	mu           sync.Mutex
	limit        int
	cooldownDur  time.Duration
	quotaCount   int
	quotaDate    string
	cooldowns    map[string]int64 // sanitized IP → Unix expiry
}

// NewMemStore creates a fresh in-memory store with the given quota limit and
// per-IP cooldown duration.
func NewMemStore(limit int, cooldown time.Duration) *MemStore {
	return &MemStore{
		limit:       limit,
		cooldownDur: cooldown,
		quotaDate:   utcDateString(),
		cooldowns:   make(map[string]int64),
	}
}

func (m *MemStore) refreshDate() {
	today := utcDateString()
	if today != m.quotaDate {
		m.quotaDate = today
		m.quotaCount = 0
	}
}

// --- Quota ---

func (m *MemStore) QuotaAllow() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refreshDate()
	return m.quotaCount < m.limit
}

func (m *MemStore) QuotaCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refreshDate()
	return m.quotaCount
}

func (m *MemStore) QuotaLimit() int { return m.limit }

func (m *MemStore) QuotaRemaining() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refreshDate()
	rem := m.limit - m.quotaCount
	if rem < 0 {
		return 0
	}
	return rem
}

func (m *MemStore) QuotaRecord() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refreshDate()
	m.quotaCount++
	return nil
}

// --- Cooldown ---

func (m *MemStore) CooldownAllow(ip string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := sanitizeIP(ip)
	expiry, ok := m.cooldowns[key]
	if !ok {
		return true
	}
	return time.Now().Unix() >= expiry
}

func (m *MemStore) CooldownRecord(ip string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := sanitizeIP(ip)
	m.cooldowns[key] = time.Now().Add(m.cooldownDur).Unix()
	return nil
}

func (m *MemStore) CooldownPrune() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().Unix()
	for k, expiry := range m.cooldowns {
		if now >= expiry {
			delete(m.cooldowns, k)
		}
	}
	return nil
}

// Close is a no-op for the in-memory store.
func (m *MemStore) Close() error { return nil }
