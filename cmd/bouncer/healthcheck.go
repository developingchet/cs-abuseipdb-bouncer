package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const (
	// healthcheckTimeout stays below the Dockerfile HEALTHCHECK --timeout (5s)
	// so the probe reports its own error instead of being killed.
	healthcheckTimeout = 4 * time.Second
	// healthcheckBodyLimit caps how much of the /healthz response is echoed
	// into `docker inspect` health logs.
	healthcheckBodyLimit = 2048
)

// errMetricsDisabled is returned when there is no HTTP server to probe.
var errMetricsDisabled = errors.New(
	"healthcheck needs the metrics/health server: set METRICS_ENABLED=true and METRICS_ADDR " +
		"(or disable the container HEALTHCHECK)")

// probeClient is a seam for tests.
var probeClient = &http.Client{Timeout: healthcheckTimeout}

// runHealthcheck asks the running bouncer for its status over HTTP. It must
// not open state.db: the running process holds bbolt's exclusive file lock,
// so a second opener would block until timeout on every probe.
func runHealthcheck(cmd *cobra.Command, _ []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("configuration error: %w", err)
	}
	if cfg.MetricsAddr == "" {
		return errMetricsDisabled
	}

	target, err := healthURL(cfg.MetricsAddr)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), healthcheckTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return fmt.Errorf("healthcheck: build request: %w", err)
	}
	resp, err := probeClient.Do(req)
	if err != nil {
		return fmt.Errorf("healthcheck: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, healthcheckBodyLimit))
	if err != nil {
		return fmt.Errorf("healthcheck: read response: %w", err)
	}
	status := strings.TrimSpace(string(body))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unhealthy (http %d): %s", resp.StatusCode, status)
	}
	if cmd != nil {
		fmt.Fprintln(cmd.OutOrStdout(), status)
	}
	return nil
}

// healthURL turns a listen address such as ":9090" or "0.0.0.0:9090" into the
// loopback URL of the /healthz endpoint.
func healthURL(listenAddr string) (string, error) {
	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return "", fmt.Errorf("healthcheck: invalid METRICS_ADDR %q: %w", listenAddr, err)
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port) + "/healthz", nil
}
