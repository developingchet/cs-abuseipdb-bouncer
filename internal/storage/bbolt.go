package storage

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	bolt "go.etcd.io/bbolt"
)

// Compile-time proof that BoltStore satisfies the Store interface.
var _ Store = (*BoltStore)(nil)

var (
	bucketQuota    = []byte("quota")
	bucketCooldown = []byte("cooldown")
	bucketRetry    = []byte("retry")
	keyToday       = []byte("today")

	boltOpenFn                = bolt.Open
	marshalQuotaRecord        = json.Marshal
	marshalRetryEntry         = json.Marshal
	createBucketIfNotExistsFn = func(tx *bolt.Tx, name []byte) (*bolt.Bucket, error) {
		return tx.CreateBucketIfNotExists(name)
	}
	deleteBucketKeyFn = func(b *bolt.Bucket, key []byte) error {
		return b.Delete(key)
	}
)

// quotaRecord is the JSON shape stored in the quota bucket.
type quotaRecord struct {
	Count int    `json:"count"`
	Date  string `json:"date"`
}

// retryEntry is the JSON shape stored in the retry bucket.
type retryEntry struct {
	IP         string `json:"ip"`       // original IP (may differ from key due to sanitization)
	Scenario   string `json:"scenario"`
	RetryAfter int64  `json:"retry_after"` // Unix timestamp
	Attempts   int    `json:"attempts"`
}

// BoltStore is an ACID bbolt-backed implementation of Store.
// It is safe for concurrent use.
type BoltStore struct {
	db       *bolt.DB
	limit    int
	cooldown time.Duration
}

// Open opens (or creates) a bbolt database at path and initialises the
// required buckets. limit is the daily report cap; cooldown is the per-IP
// suppression window.
func Open(path string, limit int, cooldown time.Duration) (*BoltStore, error) {
	db, err := boltOpenFn(path, 0o600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("storage: open %s: %w", path, err)
	}

	// Ensure buckets exist.
	if err := db.Update(func(tx *bolt.Tx) error {
		if _, err := createBucketIfNotExistsFn(tx, bucketQuota); err != nil {
			return err
		}
		if _, err := createBucketIfNotExistsFn(tx, bucketCooldown); err != nil {
			return err
		}
		_, err := createBucketIfNotExistsFn(tx, bucketRetry)
		return err
	}); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("storage: init buckets: %w", err)
	}

	return &BoltStore{db: db, limit: limit, cooldown: cooldown}, nil
}

// --- Quota ---

func (s *BoltStore) QuotaAllow() bool {
	return s.QuotaCount() < s.limit
}

func (s *BoltStore) QuotaCount() int {
	rec := s.readQuota()
	return rec.Count
}

func (s *BoltStore) QuotaLimit() int { return s.limit }

func (s *BoltStore) QuotaRemaining() int {
	rem := s.limit - s.QuotaCount()
	if rem < 0 {
		return 0
	}
	return rem
}

func (s *BoltStore) QuotaRecord() error {
	today := utcDateString()
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketQuota)
		rec := decodeQuota(b.Get(keyToday))

		// Date rollover: reset count if stored date is stale.
		if rec.Date != today {
			rec = quotaRecord{Count: 0, Date: today}
		}
		rec.Count++

		data, err := marshalQuotaRecord(rec)
		if err != nil {
			return err
		}
		return b.Put(keyToday, data)
	})
}

func (s *BoltStore) readQuota() quotaRecord {
	var rec quotaRecord
	_ = s.db.View(func(tx *bolt.Tx) error {
		rec = decodeQuota(tx.Bucket(bucketQuota).Get(keyToday))
		return nil
	})
	// Reset if date is stale.
	if rec.Date != utcDateString() {
		rec.Count = 0
	}
	return rec
}

func decodeQuota(data []byte) quotaRecord {
	if len(data) == 0 {
		return quotaRecord{Date: utcDateString()}
	}
	var rec quotaRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		log.Warn().Err(err).Msg("quota record corrupt, resetting")
		return quotaRecord{Date: utcDateString()}
	}
	return rec
}

// --- Cooldown ---

func (s *BoltStore) CooldownAllow(ip string) bool {
	key := []byte(sanitizeIP(ip))
	var allow bool
	_ = s.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(bucketCooldown).Get(key)
		if len(data) < 8 {
			allow = true
			return nil
		}
		expiry := int64(binary.BigEndian.Uint64(data))
		allow = time.Now().Unix() >= expiry
		return nil
	})
	return allow
}

func (s *BoltStore) CooldownRecord(ip string) error {
	key := []byte(sanitizeIP(ip))
	expiry := time.Now().Add(s.cooldown).Unix()
	val := make([]byte, 8)
	binary.BigEndian.PutUint64(val, uint64(expiry))
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketCooldown).Put(key, val)
	})
}

func (s *BoltStore) CooldownPrune() error {
	now := time.Now().Unix()
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketCooldown)
		c := b.Cursor()
		var toDelete [][]byte
		for k, v := c.First(); k != nil; k, v = c.Next() {
			if len(v) < 8 {
				toDelete = append(toDelete, append([]byte{}, k...))
				continue
			}
			expiry := int64(binary.BigEndian.Uint64(v))
			if now >= expiry {
				toDelete = append(toDelete, append([]byte{}, k...))
			}
		}
		for _, k := range toDelete {
			if err := deleteBucketKeyFn(b, k); err != nil {
				return err
			}
		}
		return nil
	})
}

// QuotaConsume atomically checks and consumes one quota unit in a single
// bolt.Update. Returns (true, nil) if allowed, (false, nil) if exhausted.
func (s *BoltStore) QuotaConsume() (bool, error) {
	today := utcDateString()
	allowed := false
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketQuota)
		rec := decodeQuota(b.Get(keyToday))
		if rec.Date != today {
			rec = quotaRecord{Count: 0, Date: today}
		}
		if rec.Count >= s.limit {
			return nil
		}
		rec.Count++
		allowed = true
		data, err := marshalQuotaRecord(rec)
		if err != nil {
			return err
		}
		return b.Put(keyToday, data)
	})
	return allowed, err
}

// CooldownConsume atomically checks and sets the cooldown for ip in a
// single bolt.Update. Returns (true, nil) if allowed, (false, nil) if active.
func (s *BoltStore) CooldownConsume(ip string) (bool, error) {
	key := []byte(sanitizeIP(ip))
	now := time.Now()
	allowed := false
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketCooldown)
		if data := b.Get(key); len(data) >= 8 {
			if now.Unix() < int64(binary.BigEndian.Uint64(data)) {
				return nil
			}
		}
		allowed = true
		val := make([]byte, 8)
		binary.BigEndian.PutUint64(val, uint64(now.Add(s.cooldown).Unix()))
		return b.Put(key, val)
	})
	return allowed, err
}

// --- Retry queue ---

// RetryEnqueue persists ip+scenario for retry after retryAfter.
// If an entry for this IP already exists, its Attempts counter is incremented.
func (s *BoltStore) RetryEnqueue(ip, scenario string, retryAfter time.Time) error {
	key := []byte(sanitizeIP(ip))
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketRetry)
		entry := retryEntry{IP: ip, Scenario: scenario, RetryAfter: retryAfter.Unix(), Attempts: 1}
		if existing := b.Get(key); len(existing) > 0 {
			var e retryEntry
			if err := json.Unmarshal(existing, &e); err == nil {
				entry.Attempts = e.Attempts + 1
			}
		}
		data, err := marshalRetryEntry(entry)
		if err != nil {
			return err
		}
		return b.Put(key, data)
	})
}

// RetryDequeue returns up to limit entries whose retryAfter <= now.Unix().
func (s *BoltStore) RetryDequeue(now time.Time, limit int) ([]RetryRecord, error) {
	nowUnix := now.Unix()
	var records []RetryRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketRetry)
		c := b.Cursor()
		for k, v := c.First(); k != nil && len(records) < limit; k, v = c.Next() {
			var e retryEntry
			if err := json.Unmarshal(v, &e); err != nil {
				log.Warn().Err(err).Str("key", string(k)).Msg("retry entry corrupt, skipping")
				continue
			}
			if e.RetryAfter <= nowUnix {
				records = append(records, RetryRecord{
					BucketKey: string(k),
					IP:        e.IP,
					Scenario:  e.Scenario,
					Attempts:  e.Attempts,
				})
			}
		}
		return nil
	})
	return records, err
}

// RetryDelete removes the entry identified by bucketKey from the retry bucket.
func (s *BoltStore) RetryDelete(bucketKey string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return deleteBucketKeyFn(tx.Bucket(bucketRetry), []byte(bucketKey))
	})
}

// RetryCount returns the number of entries in the retry bucket.
func (s *BoltStore) RetryCount() (int, error) {
	var count int
	err := s.db.View(func(tx *bolt.Tx) error {
		count = tx.Bucket(bucketRetry).Stats().KeyN
		return nil
	})
	return count, err
}

// RetryPrune deletes retry entries whose retryAfter timestamp is older than
// olderThan, preventing unbounded growth after a crash or long rate-limit period.
func (s *BoltStore) RetryPrune(olderThan time.Time) error {
	threshold := olderThan.Unix()
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketRetry)
		c := b.Cursor()
		var toDelete [][]byte
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var e retryEntry
			if err := json.Unmarshal(v, &e); err != nil {
				toDelete = append(toDelete, append([]byte{}, k...))
				continue
			}
			if e.RetryAfter < threshold {
				toDelete = append(toDelete, append([]byte{}, k...))
			}
		}
		for _, k := range toDelete {
			if err := deleteBucketKeyFn(b, k); err != nil {
				return err
			}
		}
		return nil
	})
}

// DBPath returns the filesystem path of the database file.
func (s *BoltStore) DBPath() string { return s.db.Path() }

// Close cleanly closes the underlying bbolt database.
func (s *BoltStore) Close() error { return s.db.Close() }
