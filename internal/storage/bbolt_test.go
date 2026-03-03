package storage

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"
)

func installBoltSeams(t *testing.T) {
	t.Helper()
	origOpen := boltOpenFn
	origMarshal := marshalQuotaRecord
	origMarshalRetry := marshalRetryEntry
	origCreateBucket := createBucketIfNotExistsFn
	origDeleteKey := deleteBucketKeyFn
	t.Cleanup(func() {
		boltOpenFn = origOpen
		marshalQuotaRecord = origMarshal
		marshalRetryEntry = origMarshalRetry
		createBucketIfNotExistsFn = origCreateBucket
		deleteBucketKeyFn = origDeleteKey
	})
}

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

func TestBoltStore_Open_BucketInitError(t *testing.T) {
	installBoltSeams(t)
	createBucketIfNotExistsFn = func(tx *bolt.Tx, name []byte) (*bolt.Bucket, error) {
		return nil, errors.New("bucket init failed")
	}

	_, err := Open(filepath.Join(t.TempDir(), "state.db"), 1000, time.Minute)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "storage: init buckets")
}

func TestBoltStore_Quota_RemainingClampedWhenCorruptCountAboveLimit(t *testing.T) {
	s := newTestStore(t, 1, time.Minute)
	rec, err := json.Marshal(quotaRecord{Count: 5, Date: utcDateString()})
	require.NoError(t, err)
	require.NoError(t, s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketQuota).Put(keyToday, rec)
	}))

	assert.Equal(t, 0, s.QuotaRemaining())
}

func TestBoltStore_QuotaCount_StaleRecordResetsOnRead(t *testing.T) {
	s := newTestStore(t, 1000, time.Minute)
	stale, err := json.Marshal(quotaRecord{Count: 123, Date: "2000-01-01"})
	require.NoError(t, err)
	require.NoError(t, s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketQuota).Put(keyToday, stale)
	}))

	assert.Equal(t, 0, s.QuotaCount())
}

func TestDecodeQuota_InvalidJSONReturnsDefault(t *testing.T) {
	rec := decodeQuota([]byte("not-json"))
	assert.Equal(t, 0, rec.Count)
	assert.Equal(t, utcDateString(), rec.Date)
}

func TestBoltStore_Cooldown_Prune_PrunesShortValues(t *testing.T) {
	s := newTestStore(t, 1000, time.Minute)
	key := []byte(sanitizeIP("10.0.0.7"))
	require.NoError(t, s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketCooldown).Put(key, []byte{1, 2, 3, 4})
	}))

	require.NoError(t, s.CooldownPrune())
	assert.True(t, s.CooldownAllow("10.0.0.7"))
}

func TestBoltStore_Cooldown_Prune_DeleteError(t *testing.T) {
	installBoltSeams(t)
	s := newTestStore(t, 1000, -1*time.Second)
	require.NoError(t, s.CooldownRecord("10.0.0.8"))

	deleteBucketKeyFn = func(*bolt.Bucket, []byte) error {
		return errors.New("delete failed")
	}
	err := s.CooldownPrune()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "delete failed")
}

func TestBoltStore_QuotaConsume_LimitReached(t *testing.T) {
	s := newTestStore(t, 1, time.Minute)
	allowed, err := s.QuotaConsume()
	require.NoError(t, err)
	assert.True(t, allowed)

	allowed, err = s.QuotaConsume()
	require.NoError(t, err)
	assert.False(t, allowed)
}

func TestBoltStore_QuotaConsume_StaleRecordBranch(t *testing.T) {
	s := newTestStore(t, 1000, time.Minute)
	stale, err := json.Marshal(quotaRecord{Count: 99, Date: "2000-01-01"})
	require.NoError(t, err)
	require.NoError(t, s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketQuota).Put(keyToday, stale)
	}))

	allowed, err := s.QuotaConsume()
	require.NoError(t, err)
	assert.True(t, allowed)
	assert.Equal(t, 1, s.QuotaCount())
}

func TestBoltStore_QuotaRecord_MarshalError(t *testing.T) {
	installBoltSeams(t)
	s := newTestStore(t, 1000, time.Minute)
	marshalQuotaRecord = func(any) ([]byte, error) {
		return nil, errors.New("marshal failed")
	}

	err := s.QuotaRecord()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "marshal failed")
}

func TestBoltStore_RetryEnqueue_MarshalError(t *testing.T) {
	installBoltSeams(t)
	s := newTestStore(t, 1000, time.Minute)
	marshalRetryEntry = func(any) ([]byte, error) {
		return nil, errors.New("marshal failed")
	}

	err := s.RetryEnqueue("10.0.0.1", "s1", time.Now().Add(-time.Second))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "marshal failed")
}

func TestBoltStore_QuotaConsume_MarshalError(t *testing.T) {
	installBoltSeams(t)
	s := newTestStore(t, 1000, time.Minute)
	marshalQuotaRecord = func(any) ([]byte, error) {
		return nil, errors.New("marshal failed")
	}

	allowed, err := s.QuotaConsume()
	assert.True(t, allowed, "allowed is set before marshal and remains true on marshal failure")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "marshal failed")
}

// --- Retry queue tests ---

func TestBoltStore_Retry_EnqueueDequeue(t *testing.T) {
	s := newTestStore(t, 1000, time.Minute)
	past := time.Now().Add(-time.Second)

	require.NoError(t, s.RetryEnqueue("203.0.113.42", "crowdsecurity/ssh-bf", past))

	records, err := s.RetryDequeue(time.Now(), 10)
	require.NoError(t, err)
	require.Len(t, records, 1)
	assert.Equal(t, "203.0.113.42", records[0].IP)
	assert.Equal(t, "crowdsecurity/ssh-bf", records[0].Scenario)
	assert.Equal(t, 1, records[0].Attempts)
	assert.NotEmpty(t, records[0].BucketKey)
}

func TestBoltStore_Retry_IgnoresFutureEntries(t *testing.T) {
	s := newTestStore(t, 1000, time.Minute)
	future := time.Now().Add(time.Hour)

	require.NoError(t, s.RetryEnqueue("203.0.113.42", "crowdsecurity/ssh-bf", future))

	records, err := s.RetryDequeue(time.Now(), 10)
	require.NoError(t, err)
	assert.Empty(t, records)
}

func TestBoltStore_Retry_Delete(t *testing.T) {
	s := newTestStore(t, 1000, time.Minute)
	past := time.Now().Add(-time.Second)

	require.NoError(t, s.RetryEnqueue("203.0.113.42", "crowdsecurity/ssh-bf", past))

	records, err := s.RetryDequeue(time.Now(), 10)
	require.NoError(t, err)
	require.Len(t, records, 1)

	require.NoError(t, s.RetryDelete(records[0].BucketKey))

	records2, err := s.RetryDequeue(time.Now(), 10)
	require.NoError(t, err)
	assert.Empty(t, records2)
}

func TestBoltStore_Retry_Count(t *testing.T) {
	s := newTestStore(t, 1000, time.Minute)

	count, err := s.RetryCount()
	require.NoError(t, err)
	assert.Equal(t, 0, count)

	require.NoError(t, s.RetryEnqueue("10.0.0.1", "s1", time.Now().Add(time.Hour)))
	require.NoError(t, s.RetryEnqueue("10.0.0.2", "s2", time.Now().Add(time.Hour)))

	count, err = s.RetryCount()
	require.NoError(t, err)
	assert.Equal(t, 2, count)
}

func TestBoltStore_Retry_IncrementAttempts(t *testing.T) {
	s := newTestStore(t, 1000, time.Minute)
	retryAt := time.Now().Add(-time.Second)

	require.NoError(t, s.RetryEnqueue("203.0.113.42", "crowdsecurity/ssh-bf", retryAt))
	require.NoError(t, s.RetryEnqueue("203.0.113.42", "crowdsecurity/ssh-bf", retryAt))

	records, err := s.RetryDequeue(time.Now(), 10)
	require.NoError(t, err)
	require.Len(t, records, 1)
	assert.Equal(t, 2, records[0].Attempts)
}

func TestBoltStore_Retry_PersistsAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")

	s1, err := Open(path, 1000, time.Minute)
	require.NoError(t, err)
	retryAt := time.Now().Add(-time.Second)
	require.NoError(t, s1.RetryEnqueue("203.0.113.42", "crowdsecurity/ssh-bf", retryAt))
	require.NoError(t, s1.Close())

	s2, err := Open(path, 1000, time.Minute)
	require.NoError(t, err)
	defer s2.Close()

	records, err := s2.RetryDequeue(time.Now(), 10)
	require.NoError(t, err)
	require.Len(t, records, 1)
	assert.Equal(t, "203.0.113.42", records[0].IP)
}

func TestBoltStore_RetryDelete_Error(t *testing.T) {
	installBoltSeams(t)
	s := newTestStore(t, 1000, time.Minute)

	past := time.Now().Add(-time.Second)
	require.NoError(t, s.RetryEnqueue("203.0.113.42", "crowdsecurity/ssh-bf", past))

	records, err := s.RetryDequeue(time.Now(), 10)
	require.NoError(t, err)
	require.Len(t, records, 1)

	deleteBucketKeyFn = func(*bolt.Bucket, []byte) error {
		return errors.New("delete failed")
	}

	err = s.RetryDelete(records[0].BucketKey)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "delete failed")
}

func TestBoltStore_RetryPrune_RemovesOldEntries(t *testing.T) {
	s := newTestStore(t, 1000, time.Minute)

	// Enqueue a past entry (older than 25 hours — will be pruned).
	veryOld := time.Now().Add(-25 * time.Hour)
	require.NoError(t, s.RetryEnqueue("10.0.0.1", "s1", veryOld))

	// Enqueue a recent entry (1 hour ago — not pruned).
	recentPast := time.Now().Add(-time.Hour)
	require.NoError(t, s.RetryEnqueue("10.0.0.2", "s2", recentPast))

	// Prune entries older than 24 hours.
	require.NoError(t, s.RetryPrune(time.Now().Add(-24*time.Hour)))

	count, err := s.RetryCount()
	require.NoError(t, err)
	assert.Equal(t, 1, count, "only the recent entry should remain after pruning")
}

func TestBoltStore_RetryPrune_CorruptEntry(t *testing.T) {
	s := newTestStore(t, 1000, time.Minute)

	// Inject a corrupt (non-JSON) entry directly into the retry bucket.
	key := []byte("corrupt-key")
	require.NoError(t, s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketRetry).Put(key, []byte("not-json"))
	}))

	// RetryPrune must delete corrupt entries without error.
	require.NoError(t, s.RetryPrune(time.Now()))

	count, err := s.RetryCount()
	require.NoError(t, err)
	assert.Equal(t, 0, count, "corrupt entry should be deleted by RetryPrune")
}

func TestBoltStore_RetryPrune_DeleteError(t *testing.T) {
	installBoltSeams(t)
	s := newTestStore(t, 1000, time.Minute)

	// Inject an entry that is old enough to be pruned.
	veryOld := time.Now().Add(-48 * time.Hour)
	require.NoError(t, s.RetryEnqueue("10.0.0.1", "s1", veryOld))

	deleteBucketKeyFn = func(*bolt.Bucket, []byte) error {
		return errors.New("delete failed")
	}

	err := s.RetryPrune(time.Now())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "delete failed")
}

func TestBoltStore_RetryDequeue_CorruptEntry(t *testing.T) {
	s := newTestStore(t, 1000, time.Minute)

	// Inject a corrupt (non-JSON) entry directly into the retry bucket.
	key := []byte("corrupt-ip")
	require.NoError(t, s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketRetry).Put(key, []byte("not-json"))
	}))

	// RetryDequeue must skip corrupt entries without error.
	records, err := s.RetryDequeue(time.Now(), 10)
	require.NoError(t, err)
	assert.Empty(t, records, "corrupt entry should be skipped by RetryDequeue")
}

func TestBoltStore_RetryEnqueue_CorruptExistingEntry(t *testing.T) {
	s := newTestStore(t, 1000, time.Minute)

	// Inject corrupt JSON for an existing IP key.
	key := []byte(sanitizeIP("10.0.0.1"))
	require.NoError(t, s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketRetry).Put(key, []byte("not-json"))
	}))

	// RetryEnqueue for the same IP — corrupt existing data means Attempts=1.
	require.NoError(t, s.RetryEnqueue("10.0.0.1", "s1", time.Now().Add(-time.Second)))

	records, err := s.RetryDequeue(time.Now(), 10)
	require.NoError(t, err)
	require.Len(t, records, 1)
	assert.Equal(t, 1, records[0].Attempts, "corrupt existing data means Attempts should reset to 1")
}

func TestBoltStore_Open_CooldownBucketInitError(t *testing.T) {
	installBoltSeams(t)
	callCount := 0
	origCreate := createBucketIfNotExistsFn
	createBucketIfNotExistsFn = func(tx *bolt.Tx, name []byte) (*bolt.Bucket, error) {
		callCount++
		if callCount == 2 { // fail on cooldown bucket (second call)
			return nil, errors.New("bucket init failed")
		}
		return origCreate(tx, name)
	}

	_, err := Open(filepath.Join(t.TempDir(), "state.db"), 1000, time.Minute)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "storage: init buckets")
}

func TestBoltStore_Open_RetryBucketInitError(t *testing.T) {
	installBoltSeams(t)
	callCount := 0
	origCreate := createBucketIfNotExistsFn
	createBucketIfNotExistsFn = func(tx *bolt.Tx, name []byte) (*bolt.Bucket, error) {
		callCount++
		if callCount == 3 { // fail on retry bucket (third call)
			return nil, errors.New("bucket init failed")
		}
		return origCreate(tx, name)
	}

	_, err := Open(filepath.Join(t.TempDir(), "state.db"), 1000, time.Minute)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "storage: init buckets")
}
