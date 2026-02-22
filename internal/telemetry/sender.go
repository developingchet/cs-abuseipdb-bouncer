package telemetry

import (
	"context"
	"time"
)

const pushTimeout = 10 * time.Second

// Pusher sends usage metrics to an upstream endpoint.
type Pusher interface {
	Push(ctx context.Context, payload MetricsPayload) error
}

// PushFunc adapts a function to the Pusher interface.
type PushFunc func(ctx context.Context, payload MetricsPayload) error

// Push implements Pusher.
func (f PushFunc) Push(ctx context.Context, payload MetricsPayload) error {
	return f(ctx, payload)
}

// Sender periodically flushes in-memory counters to /usage-metrics.
type Sender struct {
	version string
	started time.Time
	interval time.Duration
	counter *Counter
	pusher  Pusher
	now     func() time.Time
}

// NewSender builds a sender for the given interval and pusher.
func NewSender(version string, started time.Time, interval time.Duration, counter *Counter, pusher Pusher) *Sender {
	if counter == nil {
		counter = NewCounter()
	}
	if interval <= 0 {
		interval = 30 * time.Minute
	}
	return &Sender{
		version:  version,
		started:  started.UTC(),
		interval: interval,
		counter:  counter,
		pusher:   pusher,
		now:      time.Now,
	}
}

// Run flushes counters on every interval tick until ctx is canceled.
func (s *Sender) Run(ctx context.Context) {
	if s.pusher == nil || s.counter == nil {
		return
	}

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = s.Flush(ctx)
		}
	}
}

// Flush sends one usage-metrics payload and keeps counters on failure.
func (s *Sender) Flush(ctx context.Context) error {
	if s.pusher == nil || s.counter == nil {
		return nil
	}

	processed := s.counter.SnapshotAndResetProcessed()
	if processed <= 0 {
		return nil
	}

	payload := BuildMetricsPayloadAt(
		s.version,
		s.started,
		int64(s.interval.Seconds()),
		processed,
		s.now().UTC(),
	)

	pushCtx, cancel := context.WithTimeout(ctx, pushTimeout)
	defer cancel()
	if err := s.pusher.Push(pushCtx, payload); err != nil {
		// Preserve data if the push failed.
		s.counter.AddProcessed(processed)
		return err
	}

	return nil
}
