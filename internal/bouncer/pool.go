package bouncer

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/developingchet/cs-abuseipdb-bouncer/internal/decision"
	"github.com/developingchet/cs-abuseipdb-bouncer/internal/metrics"
	"github.com/developingchet/cs-abuseipdb-bouncer/internal/sink"
	"github.com/developingchet/cs-abuseipdb-bouncer/internal/storage"
	"github.com/developingchet/cs-abuseipdb-bouncer/internal/telemetry"
)

const (
	// maxDeliveryAttempts bounds how many times one decision is sent before it
	// is dropped (the first attempt plus retries from the retry queue).
	maxDeliveryAttempts = 6
	// Transient failures are retried after retryBaseDelay, doubling per
	// attempt up to retryMaxDelay.
	retryBaseDelay = time.Minute
	retryMaxDelay  = 30 * time.Minute
	// shutdownRetryDelay is used for reports interrupted by shutdown so they
	// are delivered soon after the next start.
	shutdownRetryDelay = 10 * time.Second
)

type workerJob struct {
	d       *decision.Decision
	isRetry bool
	// attempts is the number of delivery attempts already made for d
	// (0 for a fresh decision, RetryRecord.Attempts for a retry).
	attempts int
}

type workerPool struct {
	jobCh   chan workerJob
	wg      sync.WaitGroup
	store   storage.Store
	sinks   []sink.Sink
	counter *telemetry.Counter
	health  *healthState
}

// newWorkerPool creates and starts count worker goroutines, each reading from a
// buffered channel of capacity buf. Workers are stopped by cancelling ctx and
// then calling stop().
func newWorkerPool(
	ctx context.Context,
	count, buf int,
	store storage.Store,
	sinks []sink.Sink,
	counter *telemetry.Counter,
	health *healthState,
) *workerPool {
	p := &workerPool{
		jobCh:   make(chan workerJob, buf),
		store:   store,
		sinks:   sinks,
		counter: counter,
		health:  health,
	}
	for i := 0; i < count; i++ {
		p.wg.Add(1)
		go p.runWorker(ctx)
	}
	return p
}

// submit enqueues a job non-blocking. Returns false if the buffer is full and
// the job was dropped. Callers must not call submit after stop.
func (p *workerPool) submit(job workerJob) bool {
	select {
	case p.jobCh <- job:
		return true
	default:
		metrics.DecisionsSkipped.WithLabelValues("buffer_full").Inc()
		return false
	}
}

// stop closes the job channel and waits for all workers to finish draining it.
// Every goroutine that calls submit must have exited before stop is called.
func (p *workerPool) stop() {
	close(p.jobCh)
	p.wg.Wait()
}

func (p *workerPool) runWorker(ctx context.Context) {
	defer p.wg.Done()
	for job := range p.jobCh {
		p.processJob(ctx, job)
	}
}

func (p *workerPool) processJob(ctx context.Context, job workerJob) {
	d := job.d

	if !job.isRetry && !p.admit(d) {
		return
	}

	r := &sink.Report{
		IP:       d.Value,
		Scenario: d.Scenario,
	}

	reported := false
	var retryDelay time.Duration
	for _, s := range p.sinks {
		ok, delay := p.reportTo(ctx, s, r, job.attempts+1)
		reported = reported || ok
		retryDelay = max(retryDelay, delay)
	}

	if retryDelay > 0 {
		p.scheduleRetry(job, retryDelay)
	}

	if reported {
		metrics.ReportsSent.Inc()
		metrics.QuotaRemaining.Set(float64(p.store.QuotaRemaining()))
		if p.counter != nil {
			p.counter.IncProcessed()
		}
	}
}

// admit applies the stateful cooldown and quota gates to a fresh decision.
// Retries skip them: their cooldown and quota unit were consumed on the
// first attempt.
func (p *workerPool) admit(d *decision.Decision) bool {
	// 1. CooldownConsume first — so a cooldown hit never wastes quota.
	allowed, err := p.store.CooldownConsume(d.Value)
	if err != nil {
		log.Warn().Err(err).Str("ip", d.Value).Msg("cooldown consume error")
		return false
	}
	if !allowed {
		metrics.DecisionsSkipped.WithLabelValues("cooldown").Inc()
		log.Debug().Str("ip", d.Value).Msg("decision filtered (cooldown)")
		return false
	}

	// 2. QuotaConsume — only reached if the IP passed the cooldown gate.
	allowed, err = p.store.QuotaConsume()
	if err != nil {
		log.Warn().Err(err).Msg("quota consume error")
		return false
	}
	if !allowed {
		metrics.DecisionsSkipped.WithLabelValues("quota").Inc()
		log.Debug().Str("ip", d.Value).Msg("decision filtered (quota)")
		return false
	}
	return true
}

// reportTo sends r to one sink and classifies the outcome. It returns whether
// the report was accepted and, when it should be retried, the delay before
// the next attempt (0 = do not retry).
func (p *workerPool) reportTo(ctx context.Context, s sink.Sink, r *sink.Report, attempt int) (bool, time.Duration) {
	err := s.Report(ctx, r)
	var rl sink.ErrRateLimit
	var perm sink.ErrPermanent

	switch {
	case err == nil:
		p.health.recordSinkOK()
		metrics.LastReportSuccess.SetToCurrentTime()
		log.Info().Str("ip", r.IP).Str("sink", s.Name()).Msg("reported")
		return true, 0

	case errors.Is(err, sink.ErrDuplicate):
		p.health.recordSinkOK()
		metrics.DecisionsSkipped.WithLabelValues("duplicate").Inc()
		log.Debug().Str("ip", r.IP).Str("sink", s.Name()).Msg("already reported within the upstream dedup window")
		return false, 0

	case errors.As(err, &rl):
		p.health.recordSinkOK()
		return false, max(rl.RetryAfter, time.Second)

	case errors.As(err, &perm):
		p.health.recordSinkOK()
		metrics.DecisionsSkipped.WithLabelValues("rejected").Inc()
		log.Error().Err(err).Str("sink", s.Name()).Str("ip", r.IP).Msg("report rejected -- dropped")
		return false, 0

	case ctx.Err() != nil:
		// Shutting down: keep the decision for the next start.
		log.Warn().Err(err).Str("sink", s.Name()).Str("ip", r.IP).Msg("report interrupted by shutdown")
		return false, shutdownRetryDelay

	default:
		p.health.recordSinkFailure()
		log.Error().Err(err).Str("sink", s.Name()).Str("ip", r.IP).Msg("report failed")
		return false, transientRetryDelay(attempt)
	}
}

// transientRetryDelay returns the backoff before retrying after the given
// (1-based) failed attempt.
func transientRetryDelay(attempt int) time.Duration {
	d := retryBaseDelay
	for i := 1; i < attempt && d < retryMaxDelay; i++ {
		d *= 2
	}
	return min(d, retryMaxDelay)
}

// scheduleRetry persists job for another attempt after delay, or drops it
// once maxDeliveryAttempts is reached.
func (p *workerPool) scheduleRetry(job workerJob, delay time.Duration) {
	d := job.d
	attempts := job.attempts + 1
	if attempts >= maxDeliveryAttempts {
		metrics.DecisionsSkipped.WithLabelValues("retry_exhausted").Inc()
		log.Error().Str("ip", d.Value).Int("attempts", attempts).Msg("giving up after repeated failures -- decision dropped")
		return
	}
	retryAt := time.Now().Add(delay)
	if err := p.store.RetryEnqueue(d.Value, d.Scenario, retryAt, attempts); err != nil {
		log.Error().Err(err).Str("ip", d.Value).Msg("failed to enqueue retry -- decision lost")
		metrics.DecisionsSkipped.WithLabelValues("retry_enqueue_failed").Inc()
		return
	}
	log.Warn().Str("ip", d.Value).Time("retry_at", retryAt).Int("attempts", attempts).Msg("queued for retry")
	metrics.RetryQueueEnqueued.Inc()
}
