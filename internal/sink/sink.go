package sink

import (
	"context"
	"time"
)

// Report is the payload passed to sinks after filtering.
type Report struct {
	IP         string
	DecisionID int64
	Scenario   string
	Duration   time.Duration
}

// Sink receives filtered decisions and reports them to an external service.
type Sink interface {
	// Name returns the sink identifier for logging.
	Name() string

	// Report sends a single decision to the external service.
	Report(ctx context.Context, r *Report) error

	// Healthy returns nil if the sink can reach its upstream API.
	Healthy(ctx context.Context) error

	// Close performs graceful shutdown.
	Close() error
}
