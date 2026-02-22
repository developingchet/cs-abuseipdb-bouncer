package telemetry

import "sync/atomic"

// Counter tracks usage-metrics counters for the current push window.
type Counter struct {
	processed atomic.Int64
}

// NewCounter allocates a fresh telemetry counter.
func NewCounter() *Counter {
	return &Counter{}
}

// IncProcessed increments the "processed" counter by one.
func (c *Counter) IncProcessed() {
	c.processed.Add(1)
}

// AddProcessed adds n to the "processed" counter.
func (c *Counter) AddProcessed(n int64) {
	if n <= 0 {
		return
	}
	c.processed.Add(n)
}

// SnapshotAndResetProcessed atomically returns the current value and resets it.
func (c *Counter) SnapshotAndResetProcessed() int64 {
	return c.processed.Swap(0)
}

// Processed returns the current value without mutating it.
func (c *Counter) Processed() int64 {
	return c.processed.Load()
}
