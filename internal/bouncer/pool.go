package bouncer

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/rs/zerolog/log"

	"github.com/developingchet/cs-abuseipdb-bouncer/internal/decision"
	"github.com/developingchet/cs-abuseipdb-bouncer/internal/metrics"
	"github.com/developingchet/cs-abuseipdb-bouncer/internal/sink"
	"github.com/developingchet/cs-abuseipdb-bouncer/internal/storage"
	"github.com/developingchet/cs-abuseipdb-bouncer/internal/telemetry"
)

type workerJob struct{ d *decision.Decision }

type workerPool struct {
	jobCh       chan workerJob
	wg          sync.WaitGroup
	activeCount atomic.Int64
	store       storage.Store
	sinks       []sink.Sink
	counter     *telemetry.Counter
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
) *workerPool {
	p := &workerPool{
		jobCh: make(chan workerJob, buf),
		store: store,
		sinks: sinks,
		counter: counter,
	}
	for i := 0; i < count; i++ {
		p.wg.Add(1)
		go p.runWorker(ctx)
	}
	return p
}

// submit enqueues a job non-blocking. Returns false if the buffer is full and
// the job was dropped.
func (p *workerPool) submit(job workerJob) bool {
	select {
	case p.jobCh <- job:
		return true
	default:
		metrics.DecisionsSkipped.WithLabelValues("buffer-full").Inc()
		return false
	}
}

// stop closes the job channel and waits for all workers to finish draining it.
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
	p.activeCount.Add(1)
	defer p.activeCount.Add(-1)

	// 1. CooldownConsume first — so a cooldown hit never wastes quota.
	allowed, err := p.store.CooldownConsume(d.Value)
	if err != nil {
		log.Warn().Err(err).Str("ip", d.Value).Msg("cooldown consume error")
		return
	}
	if !allowed {
		metrics.DecisionsSkipped.WithLabelValues("cooldown").Inc()
		log.Debug().Str("ip", d.Value).Msg("decision filtered (cooldown)")
		return
	}

	// 2. QuotaConsume — only reached if the IP passed the cooldown gate.
	allowed, err = p.store.QuotaConsume()
	if err != nil {
		log.Warn().Err(err).Msg("quota consume error")
		return
	}
	if !allowed {
		metrics.DecisionsSkipped.WithLabelValues("quota").Inc()
		log.Debug().Str("ip", d.Value).Msg("decision filtered (quota)")
		return
	}

	// 3. Report to all sinks.
	r := &sink.Report{
		IP:       d.Value,
		Scenario: d.Scenario,
	}

	reported := false
	for _, s := range p.sinks {
		if err := s.Report(ctx, r); err != nil {
			log.Error().Err(err).Str("sink", s.Name()).Str("ip", d.Value).Msg("report failed")
			continue
		}
		log.Info().Str("ip", d.Value).Str("sink", s.Name()).Msg("reported")
		reported = true
	}

	if reported {
		metrics.ReportsSent.Inc()
		metrics.QuotaRemaining.Set(float64(p.store.QuotaRemaining()))
		if p.counter != nil {
			p.counter.IncProcessed()
		}
	}
}
