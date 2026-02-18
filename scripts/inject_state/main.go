// inject_state injects test quota and cooldown records into state.db for smoke testing.
// It is a standalone tool — not part of the module's test suite.
//
// Usage:
//
//	go run scripts/inject_state/main.go --db /path/to/state.db --cooldown-ip 203.0.113.42
package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

// quotaRecord mirrors internal/storage/bbolt.go quotaRecord.
type quotaRecord struct {
	Count int    `json:"count"`
	Date  string `json:"date"`
}

// sanitizeIP strips CIDR notation and replaces IPv6 colons with underscores,
// matching the logic in internal/storage/store.go sanitizeIP.
func sanitizeIP(raw string) string {
	// Strip CIDR
	if idx := strings.IndexByte(raw, '/'); idx != -1 {
		raw = raw[:idx]
	}
	// Parse to normalise
	addr, err := netip.ParseAddr(raw)
	if err == nil {
		raw = addr.String()
	}
	// IPv6: replace colons with underscores so the key is filesystem-safe and
	// matches what the bouncer writes.
	return strings.ReplaceAll(raw, ":", "_")
}

// utcDateString returns today's date in UTC as "YYYY-MM-DD".
func utcDateString() string {
	return time.Now().UTC().Format("2006-01-02")
}

func main() {
	dbPath := flag.String("db", "", "Path to state.db (required)")
	cooldownIP := flag.String("cooldown-ip", "", "IP to place in the cooldown bucket (required)")
	flag.Parse()

	if *dbPath == "" {
		log.Fatal("--db is required")
	}
	if *cooldownIP == "" {
		log.Fatal("--cooldown-ip is required")
	}

	db, err := bolt.Open(*dbPath, 0o600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		log.Fatalf("open %s: %v", *dbPath, err)
	}
	defer db.Close()

	// ── Write quota record ────────────────────────────────────────────────────
	today := utcDateString()
	rec := quotaRecord{Count: 42, Date: today}
	recJSON, err := json.Marshal(rec)
	if err != nil {
		log.Fatalf("marshal quota: %v", err)
	}

	err = db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("quota"))
		if err != nil {
			return fmt.Errorf("create quota bucket: %w", err)
		}
		return b.Put([]byte("today"), recJSON)
	})
	if err != nil {
		log.Fatalf("write quota: %v", err)
	}
	fmt.Printf("[inject_state] quota  bucket: key=today  value=%s\n", recJSON)

	// ── Write cooldown record ─────────────────────────────────────────────────
	expiry := time.Now().Add(15 * time.Minute).Unix()
	key := sanitizeIP(*cooldownIP)

	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(expiry))

	err = db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte("cooldown"))
		if err != nil {
			return fmt.Errorf("create cooldown bucket: %w", err)
		}
		return b.Put([]byte(key), buf[:])
	})
	if err != nil {
		log.Fatalf("write cooldown: %v", err)
	}
	fmt.Printf("[inject_state] cooldown bucket: key=%s value=unix(%d) expires=%s\n",
		key, expiry, time.Unix(expiry, 0).UTC().Format(time.RFC3339))

	fmt.Println("[inject_state] done — restart the container to observe loaded state")
}
