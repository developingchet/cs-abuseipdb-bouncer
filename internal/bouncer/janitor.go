package bouncer

import (
	"context"
	"os"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/developingchet/cs-abuseipdb-bouncer/internal/metrics"
	"github.com/developingchet/cs-abuseipdb-bouncer/internal/storage"
)

// runJanitor runs periodic background maintenance tasks:
//   - Prune expired cooldown entries from the store.
//   - Update the BboltDBSizeBytes Prometheus gauge (for on-disk stores).
//
// It returns when ctx is cancelled.
func runJanitor(ctx context.Context, store storage.Store, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := store.CooldownPrune(); err != nil {
				log.Warn().Err(err).Msg("janitor: cooldown prune failed")
			}
			if path := store.DBPath(); path != "" {
				if info, err := os.Stat(path); err == nil {
					metrics.BboltDBSizeBytes.Set(float64(info.Size()))
				}
			}
		}
	}
}
