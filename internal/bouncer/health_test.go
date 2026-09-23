package bouncer

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeClock is a manually advanced clock for health tests.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newTestHealth(poll time.Duration) (*healthState, *fakeClock) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	return newHealthState(poll, clk.now), clk
}

func TestHealth_StaleAfterFloorAndMultiplier(t *testing.T) {
	h, _ := newTestHealth(2 * time.Second)
	assert.Equal(t, minHealthStaleAfter, h.staleAfter)

	h, _ = newTestHealth(time.Minute)
	assert.Equal(t, 5*time.Minute, h.staleAfter)
}

func TestHealth_StartupGraceThenUnhealthyWithoutPull(t *testing.T) {
	h, clk := newTestHealth(time.Second)

	_, err := h.live()
	require.NoError(t, err, "live during startup grace")

	clk.advance(minHealthStaleAfter + time.Second)
	r, err := h.live()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no successful LAPI pull since startup")
	assert.Equal(t, "unhealthy", r.Status)
}

func TestHealth_StalePull(t *testing.T) {
	h, clk := newTestHealth(time.Second)
	h.recordLAPIPull()

	r, err := h.live()
	require.NoError(t, err)
	assert.Equal(t, "ok", r.Status)
	assert.NotEmpty(t, r.LastLAPIPull)

	clk.advance(minHealthStaleAfter + time.Second)
	_, err = h.live()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "last successful LAPI pull was")

	h.recordLAPIPull()
	_, err = h.live()
	assert.NoError(t, err, "a fresh pull restores health")
}

func TestHealth_SinkFailuresThreshold(t *testing.T) {
	h, _ := newTestHealth(time.Second)
	h.recordLAPIPull()

	for i := 0; i < maxConsecutiveSinkFailures-1; i++ {
		h.recordSinkFailure()
	}
	_, err := h.live()
	require.NoError(t, err, "below threshold")

	h.recordSinkFailure()
	r, err := h.live()
	require.Error(t, err)
	assert.NotEmpty(t, r.LastAbuseIPDBFailure)

	h.recordSinkOK()
	r, err = h.live()
	require.NoError(t, err)
	assert.EqualValues(t, 0, r.ConsecutiveAbuseIPDBFailures)
	assert.NotEmpty(t, r.LastAbuseIPDBOK)
}

func TestHealth_ReadyNeedsFirstPull(t *testing.T) {
	h, _ := newTestHealth(time.Second)
	_, err := h.ready()
	require.Error(t, err)

	h.recordLAPIPull()
	_, err = h.ready()
	assert.NoError(t, err)
}

func TestHealth_NilReceiverIsNoop(t *testing.T) {
	var h *healthState
	assert.NotPanics(t, func() {
		h.recordLAPIPull()
		h.recordSinkOK()
		h.recordSinkFailure()
	})
}
