package bouncer

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/developingchet/cs-abuseipdb-bouncer/internal/metrics"
	"github.com/developingchet/cs-abuseipdb-bouncer/internal/sink"
	"github.com/developingchet/cs-abuseipdb-bouncer/internal/storage"
)

// errSink returns err from every Report call.
type errSink struct{ err error }

func (s *errSink) Name() string                               { return "err" }
func (s *errSink) Report(context.Context, *sink.Report) error { return s.err }
func (s *errSink) Close() error                               { return nil }

func newOutcomePool(store storage.Store, s sink.Sink) *workerPool {
	return &workerPool{
		store:  store,
		sinks:  []sink.Sink{s},
		health: newHealthState(time.Second, time.Now),
	}
}

func dueRetries(t *testing.T, store storage.Store) []storage.RetryRecord {
	t.Helper()
	recs, err := store.RetryDequeue(time.Now().Add(365*24*time.Hour), 10)
	require.NoError(t, err)
	return recs
}

func TestProcessJob_TransientFailure_QueuedWithAttempts(t *testing.T) {
	store := storage.NewMemStore(100, time.Minute)
	p := newOutcomePool(store, &errSink{err: errors.New("connection refused")})

	p.processJob(context.Background(), workerJob{d: makeDecision("203.0.113.10")})

	recs := dueRetries(t, store)
	require.Len(t, recs, 1)
	assert.Equal(t, "203.0.113.10", recs[0].IP)
	assert.Equal(t, 1, recs[0].Attempts)
	assert.EqualValues(t, 1, p.health.sinkFailures.Load())
}

func TestProcessJob_RetryCarriesAttempts(t *testing.T) {
	store := storage.NewMemStore(100, time.Minute)
	p := newOutcomePool(store, &errSink{err: errors.New("503")})

	p.processJob(context.Background(), workerJob{d: makeDecision("203.0.113.11"), isRetry: true, attempts: 3})

	recs := dueRetries(t, store)
	require.Len(t, recs, 1)
	assert.Equal(t, 4, recs[0].Attempts)
}

func TestProcessJob_RetryExhausted_Dropped(t *testing.T) {
	store := storage.NewMemStore(100, time.Minute)
	p := newOutcomePool(store, &errSink{err: errors.New("503")})
	before := testutil.ToFloat64(metrics.DecisionsSkipped.WithLabelValues("retry_exhausted"))

	p.processJob(context.Background(), workerJob{d: makeDecision("203.0.113.12"), isRetry: true, attempts: maxDeliveryAttempts - 1})

	assert.Empty(t, dueRetries(t, store))
	assert.Equal(t, before+1, testutil.ToFloat64(metrics.DecisionsSkipped.WithLabelValues("retry_exhausted")))
}

func TestProcessJob_Duplicate_NotRetriedNotCounted(t *testing.T) {
	store := storage.NewMemStore(100, time.Minute)
	p := newOutcomePool(store, &errSink{err: sink.ErrDuplicate})
	sentBefore := testutil.ToFloat64(metrics.ReportsSent)
	dupBefore := testutil.ToFloat64(metrics.DecisionsSkipped.WithLabelValues("duplicate"))

	p.processJob(context.Background(), workerJob{d: makeDecision("203.0.113.13")})

	assert.Empty(t, dueRetries(t, store))
	assert.Equal(t, sentBefore, testutil.ToFloat64(metrics.ReportsSent))
	assert.Equal(t, dupBefore+1, testutil.ToFloat64(metrics.DecisionsSkipped.WithLabelValues("duplicate")))
	assert.EqualValues(t, 0, p.health.sinkFailures.Load())
}

func TestProcessJob_Permanent_Dropped(t *testing.T) {
	store := storage.NewMemStore(100, time.Minute)
	p := newOutcomePool(store, &errSink{err: sink.ErrPermanent{Err: errors.New("422")}})
	before := testutil.ToFloat64(metrics.DecisionsSkipped.WithLabelValues("rejected"))

	p.processJob(context.Background(), workerJob{d: makeDecision("203.0.113.14")})

	assert.Empty(t, dueRetries(t, store))
	assert.Equal(t, before+1, testutil.ToFloat64(metrics.DecisionsSkipped.WithLabelValues("rejected")))
}

func TestProcessJob_Unauthorized_CountsAsFailureAndRetries(t *testing.T) {
	store := storage.NewMemStore(100, time.Minute)
	p := newOutcomePool(store, &errSink{err: sink.ErrUnauthorized})

	p.processJob(context.Background(), workerJob{d: makeDecision("203.0.113.15")})

	assert.Len(t, dueRetries(t, store), 1)
	assert.EqualValues(t, 1, p.health.sinkFailures.Load())
}

func TestProcessJob_ShutdownInterruption_Queued(t *testing.T) {
	store := storage.NewMemStore(100, time.Minute)
	p := newOutcomePool(store, &errSink{err: context.Canceled})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	p.processJob(ctx, workerJob{d: makeDecision("203.0.113.16")})

	recs := dueRetries(t, store)
	require.Len(t, recs, 1)
	assert.EqualValues(t, 0, p.health.sinkFailures.Load(), "shutdown is not an upstream failure")
}

func TestProcessJob_RateLimitUsesRetryAfter(t *testing.T) {
	store := storage.NewMemStore(100, time.Minute)
	p := newOutcomePool(store, &rateLimitSink{retryAfter: time.Hour})

	p.processJob(context.Background(), workerJob{d: makeDecision("203.0.113.17")})

	due, err := store.RetryDequeue(time.Now().Add(59*time.Minute), 10)
	require.NoError(t, err)
	assert.Empty(t, due, "must not be due before Retry-After")
	assert.Len(t, dueRetries(t, store), 1)
}

func TestProcessJob_Success_ResetsFailuresAndStampsMetric(t *testing.T) {
	store := storage.NewMemStore(100, time.Minute)
	p := newOutcomePool(store, &countingSink{})
	p.health.recordSinkFailure()

	p.processJob(context.Background(), workerJob{d: makeDecision("203.0.113.18")})

	assert.EqualValues(t, 0, p.health.sinkFailures.Load())
	assert.Greater(t, testutil.ToFloat64(metrics.LastReportSuccess), float64(0))
}

func TestTransientRetryDelay(t *testing.T) {
	assert.Equal(t, time.Minute, transientRetryDelay(1))
	assert.Equal(t, 2*time.Minute, transientRetryDelay(2))
	assert.Equal(t, 16*time.Minute, transientRetryDelay(5))
	assert.Equal(t, retryMaxDelay, transientRetryDelay(50))
}
