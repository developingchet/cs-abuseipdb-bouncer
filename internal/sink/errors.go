package sink

import (
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
