package storage

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Compile-time proof that BoltStore satisfies the Store interface.
var _ Store = (*BoltStore)(nil)

var (
	bucketQuota    = []byte("quota")
	bucketCooldown = []byte("cooldown")
	keyToday       = []byte("today")
)

// quotaRecord is the JSON shape stored in the quota bucket.
type quotaRecord struct {
	Count int    `json:"count"`
	Date  string `json:"date"`
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
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("storage: open %s: %w", path, err)
	}

	// Ensure buckets exist.
	if err := db.Update(func(tx *bolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists(bucketQuota); err != nil {
			return err
		}
		_, err := tx.CreateBucketIfNotExists(bucketCooldown)
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

		data, err := json.Marshal(rec)
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
			if err := b.Delete(k); err != nil {
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
		data, err := json.Marshal(rec)
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

// DBPath returns the filesystem path of the database file.
func (s *BoltStore) DBPath() string { return s.db.Path() }

// Close cleanly closes the underlying bbolt database.
func (s *BoltStore) Close() error { return s.db.Close() }
