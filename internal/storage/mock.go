package storage

import (
	"sync"
	"time"
)

// MemStore is an in-memory implementation of Store for use in unit tests.
// It is exported so that bouncer_test.go can import it without creating a
// file on disk.
type MemStore struct {
	mu          sync.Mutex
	limit       int
	cooldownDur time.Duration
	quotaCount  int
	quotaDate   string
	cooldowns   map[string]int64 // sanitized IP → Unix expiry
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

// QuotaConsume atomically checks and consumes one quota unit.
// Returns (true, nil) if allowed, (false, nil) if exhausted.
func (m *MemStore) QuotaConsume() (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refreshDate()
	if m.quotaCount >= m.limit {
		return false, nil
	}
	m.quotaCount++
	return true, nil
}

// CooldownConsume atomically checks and sets the cooldown for ip.
// Returns (true, nil) if allowed, (false, nil) if active.
func (m *MemStore) CooldownConsume(ip string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := sanitizeIP(ip)
	now := time.Now()
	if expiry, ok := m.cooldowns[key]; ok {
		if now.Unix() < expiry {
			return false, nil
		}
	}
	m.cooldowns[key] = now.Add(m.cooldownDur).Unix()
	return true, nil
}

// DBPath returns "" because MemStore is in-memory.
func (m *MemStore) DBPath() string { return "" }

// Close is a no-op for the in-memory store.
func (m *MemStore) Close() error { return nil }
