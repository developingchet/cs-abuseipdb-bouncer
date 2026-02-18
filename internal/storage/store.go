package storage

import "time"

// Store is the single persistence abstraction replacing *state.Quota and
// *state.Cooldown. Implementations must be safe for concurrent use.
type Store interface {
	QuotaAllow() bool
	QuotaCount() int
	QuotaLimit() int
	QuotaRemaining() int  // limit - count, clamped to zero
	QuotaRecord() error

	CooldownAllow(ip string) bool
	CooldownRecord(ip string) error
	CooldownPrune() error

	Close() error
}

// sanitizeIP replaces characters that are invalid or ambiguous in bbolt keys.
// Strip CIDR suffix and replace IPv6 colons with underscores.
func sanitizeIP(ip string) string {
	// Strip CIDR suffix if present.
	for i := 0; i < len(ip); i++ {
		if ip[i] == '/' {
			ip = ip[:i]
			break
		}
	}
	// Replace colons (IPv6) with underscores.
	result := make([]byte, len(ip))
	for i := 0; i < len(ip); i++ {
		if ip[i] == ':' {
			result[i] = '_'
		} else {
			result[i] = ip[i]
		}
	}
	return string(result)
}

// utcDateString returns the current UTC date as "YYYY-MM-DD".
func utcDateString() string {
	return time.Now().UTC().Format("2006-01-02")
}
