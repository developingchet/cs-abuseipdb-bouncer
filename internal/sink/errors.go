package sink

import (
	"errors"
	"fmt"
	"time"
)

// ErrRateLimit is returned when the upstream API is rate-limiting this client.
// The caller must not sleep; instead it should persist the decision for later retry.
type ErrRateLimit struct {
	RetryAfter time.Duration
}

func (e ErrRateLimit) Error() string {
	return fmt.Sprintf("rate limited: retry after %s", e.RetryAfter)
}

// ErrDuplicate is returned when the upstream API refused the report because
// the same IP was already reported recently (AbuseIPDB: once per 15 minutes).
// The report is redundant, so callers should neither retry it nor count it as
// a failure.
var ErrDuplicate = errors.New("duplicate report rejected by upstream")

// ErrUnauthorized is returned when the upstream API rejected the credentials.
// It is retryable: queued reports are delivered once the key is fixed.
var ErrUnauthorized = errors.New("unauthorized: upstream rejected the API key")

// ErrPermanent wraps failures that retrying cannot fix (invalid parameters,
// rejected credentials). Callers should drop the report instead of queueing it.
type ErrPermanent struct {
	Err error
}

func (e ErrPermanent) Error() string { return "permanent failure: " + e.Err.Error() }

func (e ErrPermanent) Unwrap() error { return e.Err }
