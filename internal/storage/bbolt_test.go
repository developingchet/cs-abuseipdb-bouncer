package storage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"
)

func newTestStore(t *testing.T, limit int, cooldown time.Duration) *BoltStore {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "state.db"), limit, cooldown)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// --- Quota tests ---

func TestBoltStore_Quota_FreshStart(t *testing.T) {
	s := newTestStore(t, 1000, time.Minute)
	assert.Equal(t, 0, s.QuotaCount())
	assert.True(t, s.QuotaAllow())
}

func TestBoltStore_Quota_IncrementAndRead(t *testing.T) {
	s := newTestStore(t, 1000, time.Minute)

	require.NoError(t, s.QuotaRecord())
	require.NoError(t, s.QuotaRecord())
	require.NoError(t, s.QuotaRecord())

	assert.Equal(t, 3, s.QuotaCount())
	assert.True(t, s.QuotaAllow())
}

func TestBoltStore_Quota_LimitEnforced(t *testing.T) {
	s := newTestStore(t, 3, time.Minute)

	require.NoError(t, s.QuotaRecord())
	require.NoError(t, s.QuotaRecord())
	require.NoError(t, s.QuotaRecord())

	assert.Equal(t, 3, s.QuotaCount())
	assert.False(t, s.QuotaAllow())
}

func TestBoltStore_Quota_LimitValue(t *testing.T) {
	s := newTestStore(t, 500, time.Minute)
	assert.Equal(t, 500, s.QuotaLimit())
}

func TestBoltStore_Quota_Remaining(t *testing.T) {
	s := newTestStore(t, 10, time.Minute)
	assert.Equal(t, 10, s.QuotaRemaining())
	require.NoError(t, s.QuotaRecord())
	assert.Equal(t, 9, s.QuotaRemaining())
}

func TestBoltStore_Quota_RemainingClampedToZero(t *testing.T) {
	s := newTestStore(t, 1, time.Minute)
	require.NoError(t, s.QuotaRecord()) // count = 1 == limit
	assert.Equal(t, 0, s.QuotaRemaining())
}

func TestBoltStore_Quota_PersistsAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")

	s1, err := Open(path, 1000, time.Minute)
	require.NoError(t, err)
	require.NoError(t, s1.QuotaRecord())
	require.NoError(t, s1.QuotaRecord())
	assert.Equal(t, 2, s1.QuotaCount())
	require.NoError(t, s1.Close())

	// Reopen and confirm count survived restart.
	s2, err := Open(path, 1000, time.Minute)
	require.NoError(t, err)
	defer s2.Close()
	assert.Equal(t, 2, s2.QuotaCount())
}

// TestBoltStore_Quota_DateRollover injects a stale quota record directly
// into the bucket and confirms that the next QuotaRecord() resets to 1.
func TestBoltStore_Quota_DateRollover(t *testing.T) {
	s := newTestStore(t, 1000, time.Minute)

	// Inject stale record with yesterday's date.
	stale, _ := json.Marshal(quotaRecord{Count: 999, Date: "2000-01-01"})
	require.NoError(t, s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketQuota).Put(keyToday, stale)
	}))

	// QuotaRecord() must detect stale date, reset count to 0, then increment to 1.
	require.NoError(t, s.QuotaRecord())
	assert.Equal(t, 1, s.QuotaCount())
}

// --- Cooldown tests ---

func TestBoltStore_Cooldown_AllowsUnseenIP(t *testing.T) {
	s := newTestStore(t, 1000, time.Minute)
	assert.True(t, s.CooldownAllow("203.0.113.42"))
}

func TestBoltStore_Cooldown_BlocksAfterRecord(t *testing.T) {
	s := newTestStore(t, 1000, time.Minute)
	require.NoError(t, s.CooldownRecord("203.0.113.42"))
	assert.False(t, s.CooldownAllow("203.0.113.42"))
}

func TestBoltStore_Cooldown_AllowsAfterExpiry(t *testing.T) {
	// Use a negative duration so the expiry is immediately in the past.
	s := newTestStore(t, 1000, -1*time.Second)
	require.NoError(t, s.CooldownRecord("203.0.113.42"))
	assert.True(t, s.CooldownAllow("203.0.113.42"))
}

func TestBoltStore_Cooldown_IndependentPerIP(t *testing.T) {
	s := newTestStore(t, 1000, time.Minute)
	require.NoError(t, s.CooldownRecord("203.0.113.42"))
	assert.False(t, s.CooldownAllow("203.0.113.42"))
	assert.True(t, s.CooldownAllow("203.0.113.99"))
}

func TestBoltStore_Cooldown_IPv6(t *testing.T) {
	s := newTestStore(t, 1000, time.Minute)
	require.NoError(t, s.CooldownRecord("2001:db8::1"))
	assert.False(t, s.CooldownAllow("2001:db8::1"))
	assert.True(t, s.CooldownAllow("2001:db8::2"))
}

func TestBoltStore_Cooldown_CIDRStripped(t *testing.T) {
	s := newTestStore(t, 1000, time.Minute)
	require.NoError(t, s.CooldownRecord("203.0.113.42/32"))
	assert.False(t, s.CooldownAllow("203.0.113.42"))
}

func TestBoltStore_Cooldown_Prune(t *testing.T) {
	// Expired duration → expiry in the past → prune should delete both keys.
	s := newTestStore(t, 1000, -1*time.Second)
	require.NoError(t, s.CooldownRecord("10.0.0.1"))
	require.NoError(t, s.CooldownRecord("10.0.0.2"))
	require.NoError(t, s.CooldownPrune())
	assert.True(t, s.CooldownAllow("10.0.0.1"))
	assert.True(t, s.CooldownAllow("10.0.0.2"))
}

func TestBoltStore_Cooldown_Prune_KeepsActive(t *testing.T) {
	s := newTestStore(t, 1000, time.Minute)
	require.NoError(t, s.CooldownRecord("10.0.0.1")) // active

	// Manually insert an expired entry.
	expiredKey := []byte(sanitizeIP("10.0.0.2"))
	val := make([]byte, 8)
	// expiry = 0 → in the past
	require.NoError(t, s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketCooldown).Put(expiredKey, val)
	}))

	require.NoError(t, s.CooldownPrune())
	assert.False(t, s.CooldownAllow("10.0.0.1"), "active cooldown should remain")
	assert.True(t, s.CooldownAllow("10.0.0.2"), "expired entry should be pruned")
}

// --- Locking / permission / directory tests ---

func TestBoltStore_DatabaseLocking(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")

	s1, err := Open(path, 1000, time.Minute)
	require.NoError(t, err)
	defer s1.Close()

	// Second Open must time out (bbolt holds an exclusive file lock).
	// The hardcoded bolt Timeout of 2s means this sub-test takes ~2 seconds.
	_, err = Open(path, 1000, time.Minute)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timeout",
		"second Open should fail with the bbolt ErrTimeout message")
}

func TestBoltStore_FilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file-mode bits are not applicable on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")

	s, err := Open(path, 1000, time.Minute)
	require.NoError(t, err)
	_ = s.Close()

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(),
		"state.db must be owner-read/write only (0600)")
}

func TestBoltStore_ReadOnlyDirectory_FailsGracefully(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory write semantics differ on Windows")
	}
	if os.Getuid() == 0 {
		t.Skip("root bypasses permission checks; test not meaningful")
	}
	dir := t.TempDir()
	roDir := filepath.Join(dir, "readonly")
	require.NoError(t, os.Mkdir(roDir, 0o555))

	_, err := Open(filepath.Join(roDir, "state.db"), 1000, time.Minute)
	require.Error(t, err, "Open should fail when DATA_DIR is not writable")
	assert.Contains(t, err.Error(), "storage: open",
		"error must include the wrapped storage prefix for operator visibility")
}

// --- sanitizeIP tests (package-level function) ---

func TestSanitizeIP(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"203.0.113.42", "203.0.113.42"},
		{"203.0.113.42/32", "203.0.113.42"},
		{"2001:db8::1", "2001_db8__1"},
		{"2001:db8::1/128", "2001_db8__1"},
		{"::1", "__1"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.expected, sanitizeIP(tt.input), "input=%s", tt.input)
	}
}
