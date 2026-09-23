package abuseipdb

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/developingchet/cs-abuseipdb-bouncer/internal/metrics"
	"github.com/developingchet/cs-abuseipdb-bouncer/internal/sink"
)

// respBufPool reuses response body buffers across concurrent requests to
// reduce GC pressure from short-lived HTTP responses.
var respBufPool = sync.Pool{
	New: func() any { return bytes.NewBuffer(make([]byte, 0, httpResponseBufSize)) },
}

const (
	defaultReportURL      = "https://api.abuseipdb.com/api/v2/report"
	defaultCheckURL       = "https://api.abuseipdb.com/api/v2/check"
	reportTimeout         = 15 * time.Second
	checkTimeout          = 10 * time.Second
	defaultMaxRetries     = 3
	defaultInitialBackoff = 5 * time.Second
	httpResponseBufSize   = 4096
	defaultRetryAfterSecs = 60
	maxRetryAfter         = 24 * time.Hour
)

// ClientConfig holds configuration for the AbuseIPDB client.
type ClientConfig struct {
	APIKey    string
	Precheck  bool
	ReportURL string // Override for testing
	CheckURL  string // Override for testing
	MaxRetries     int
	InitialBackoff time.Duration
	SleepFn        func(time.Duration)
}

// Client implements the sink.Sink interface for AbuseIPDB.
type Client struct {
	apiKey     string
	precheck   bool
	reportURL  string
	checkURL   string
	httpClient *http.Client
	maxRetries     int
	initialBackoff time.Duration
	sleepFn        func(time.Duration)
	customSleepFn  bool
}

// Compile-time interface check.
var _ sink.Sink = (*Client)(nil)

// NewClient creates a new AbuseIPDB sink client.
func NewClient(cfg ClientConfig) *Client {
	reportURL := cfg.ReportURL
	if reportURL == "" {
		reportURL = defaultReportURL
	}
	checkURL := cfg.CheckURL
	if checkURL == "" {
		checkURL = defaultCheckURL
	}
	maxRetries := cfg.MaxRetries
	if maxRetries <= 0 {
		maxRetries = defaultMaxRetries
	}
	initialBackoff := cfg.InitialBackoff
	if initialBackoff <= 0 {
		initialBackoff = defaultInitialBackoff
	}
	sleepFn := cfg.SleepFn
	if sleepFn == nil {
		sleepFn = time.Sleep
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	return &Client{
		apiKey:    cfg.APIKey,
		precheck:  cfg.Precheck,
		reportURL: reportURL,
		checkURL:  checkURL,
		httpClient: &http.Client{
			Transport: transport,
		},
		maxRetries:     maxRetries,
		initialBackoff: initialBackoff,
		sleepFn:        sleepFn,
		customSleepFn:  cfg.SleepFn != nil,
	}
}

func (c *Client) Name() string { return "abuseipdb" }

// Report sends an IP report to AbuseIPDB with retry logic.
func (c *Client) Report(ctx context.Context, r *sink.Report) error {
	ip := stripCIDR(r.IP)
	cats := MapScenario(r.Scenario)
	comment := fmt.Sprintf("CrowdSec detection | scenario: %s", stripAuthor(r.Scenario))

	// Optional pre-check
	if c.precheck {
		whitelisted, err := c.checkWhitelisted(ctx, ip)
		if err != nil {
			log.Warn().Err(err).Str("ip", ip).Msg("precheck error, proceeding with report")
		} else if whitelisted {
			log.Info().Str("ip", ip).Msg("skip whitelisted")
			return nil
		}
	}

	catStr := formatCategories(cats)
	log.Info().
		Str("ip", ip).
		Int64("id", r.DecisionID).
		Str("scenario", stripAuthor(r.Scenario)).
		Str("cats", catStr).
		Msg("reporting")

	err := c.reportWithRetry(ctx, ip, catStr, comment)
	if err != nil {
		return err
	}

	return nil
}

func (c *Client) reportWithRetry(ctx context.Context, ip, categories, comment string) error {
	backoff := c.initialBackoff

	for attempt := 1; attempt <= c.maxRetries; attempt++ {
		code, header, body, err := c.doReport(ctx, ip, categories, comment)
		if err != nil {
			// Distinguish context deadline exceeded from other network errors.
			if ctx.Err() != nil {
				metrics.APIErrors.WithLabelValues("timeout").Inc()
				return ctx.Err()
			}
			metrics.APIErrors.WithLabelValues("network").Inc()
			if attempt < c.maxRetries {
				log.Warn().
					Int("attempt", attempt).
					Int("max", c.maxRetries).
					Dur("wait", backoff).
					Str("ip", ip).
					Msg("retry")
				if err := c.sleepWithContext(ctx, backoff); err != nil {
					return err
				}
				backoff *= 2
				continue
			}
			return fmt.Errorf("all %d attempts failed for ip=%s: %w", c.maxRetries, ip, err)
		}

		switch code {
		case http.StatusOK:
			return nil

		case http.StatusUnprocessableEntity:
			// 422 is AbuseIPDB's validation error (malformed IP, bad
			// categories). Resending the same payload cannot succeed.
			metrics.APIErrors.WithLabelValues("validation").Inc()
			detail := extractErrorDetail(body)
			log.Error().Str("ip", ip).Str("detail", detail).Msg("report rejected as invalid (422)")
			return sink.ErrPermanent{Err: fmt.Errorf("invalid report parameters (422): %s", detail)}

		case http.StatusTooManyRequests:
			detail := extractErrorDetail(body)
			if isDuplicateReport(detail) {
				log.Debug().Str("ip", ip).Str("detail", detail).Msg("skip duplicate (reported within the last 15 minutes)")
				return sink.ErrDuplicate
			}
			metrics.APIErrors.WithLabelValues("rate_limit").Inc()
			wait := retryAfter(header, body, time.Now())
			log.Warn().
				Str("ip", ip).
				Dur("retry_after", wait).
				Str("detail", detail).
				Msg("rate-limited -- decision queued for retry")
			return sink.ErrRateLimit{RetryAfter: wait}

		case http.StatusUnauthorized:
			metrics.APIErrors.WithLabelValues("auth").Inc()
			log.Error().Msg("401 unauthorized -- verify ABUSEIPDB_API_KEY")
			return fmt.Errorf("%w (401)", sink.ErrUnauthorized)

		default:
			log.Warn().Int("http", code).Str("ip", ip).Msg("unexpected response")
			if attempt < c.maxRetries {
				log.Warn().
					Int("attempt", attempt).
					Int("max", c.maxRetries).
					Dur("wait", backoff).
					Str("ip", ip).
					Msg("retry")
				if err := c.sleepWithContext(ctx, backoff); err != nil {
					return err
				}
				backoff *= 2
				continue
			}
			return fmt.Errorf("unexpected http %d for ip=%s", code, ip)
		}
	}

	return fmt.Errorf("all %d attempts exhausted for ip=%s", c.maxRetries, ip)
}

func (c *Client) doReport(ctx context.Context, ip, categories, comment string) (int, http.Header, []byte, error) {
	form := url.Values{
		"ip":         {ip},
		"categories": {categories},
		"comment":    {comment},
	}

	ctx, cancel := context.WithTimeout(ctx, reportTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.reportURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return 0, nil, nil, err
	}

	req.Header.Set("Key", c.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()

	buf := respBufPool.Get().(*bytes.Buffer) //nolint:errcheck // pool only contains *bytes.Buffer
	buf.Reset()
	defer respBufPool.Put(buf)
	_, _ = io.Copy(buf, io.LimitReader(resp.Body, httpResponseBufSize))
	body := make([]byte, buf.Len())
	copy(body, buf.Bytes())
	return resp.StatusCode, resp.Header, body, nil
}

func (c *Client) checkWhitelisted(ctx context.Context, ip string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()

	u := fmt.Sprintf("%s?ipAddress=%s&maxAgeInDays=1", c.checkURL, url.QueryEscape(ip))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return false, err
	}

	req.Header.Set("Key", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	buf := respBufPool.Get().(*bytes.Buffer) //nolint:errcheck // pool only contains *bytes.Buffer
	buf.Reset()
	defer respBufPool.Put(buf)
	_, _ = io.Copy(buf, io.LimitReader(resp.Body, httpResponseBufSize))
	body := make([]byte, buf.Len())
	copy(body, buf.Bytes())

	if resp.StatusCode != http.StatusOK {
		// /check has its own daily quota; a 429 here must not be read as
		// "not whitelisted" without telling the operator.
		return false, fmt.Errorf("check returned http %d: %s", resp.StatusCode, extractErrorDetail(body))
	}

	var result struct {
		Data struct {
			IsWhitelisted bool `json:"isWhitelisted"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return false, err
	}

	return result.Data.IsWhitelisted, nil
}

func (c *Client) Close() error { return nil }

func (c *Client) sleepWithContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	if !c.customSleepFn {
		timer := time.NewTimer(d)
		defer timer.Stop()
		select {
		case <-timer.C:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	done := make(chan struct{})
	go func() {
		c.sleepFn(d)
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// --- helpers ---

func stripCIDR(ip string) string {
	if idx := strings.IndexByte(ip, '/'); idx != -1 {
		return ip[:idx]
	}
	return ip
}

func stripAuthor(scenario string) string {
	if idx := strings.LastIndex(scenario, "/"); idx != -1 {
		return scenario[idx+1:]
	}
	return scenario
}

func formatCategories(cats []int) string {
	parts := make([]string, len(cats))
	for i, c := range cats {
		parts[i] = strconv.Itoa(c)
	}
	return strings.Join(parts, ",")
}

// retryAfterRegex extracts the seconds from rate-limit messages such as
// "Try again in 42 seconds." Matching on "in N second" avoids false-positives
// from other numbers in the message (e.g. "rate limit of 1000 requests").
var retryAfterRegex = regexp.MustCompile(`\bin\s+(\d+)\s+second`)

// retryAfter determines how long to wait after a 429. AbuseIPDB documents a
// Retry-After header (seconds) and X-RateLimit-Reset (epoch seconds of the
// daily reset); the message body is only a last resort. The result is capped
// at maxRetryAfter.
func retryAfter(h http.Header, body []byte, now time.Time) time.Duration {
	wait := time.Duration(defaultRetryAfterSecs) * time.Second
	if secs, err := strconv.ParseInt(strings.TrimSpace(h.Get("Retry-After")), 10, 64); err == nil && secs > 0 {
		wait = time.Duration(secs) * time.Second
	} else if reset, err := strconv.ParseInt(strings.TrimSpace(h.Get("X-RateLimit-Reset")), 10, 64); err == nil && reset > now.Unix() {
		wait = time.Unix(reset, 0).Sub(now)
	} else if n := extractRetryAfter(body); n > 0 {
		wait = time.Duration(n) * time.Second
	}
	return min(wait, maxRetryAfter)
}

// extractRetryAfter returns the "in N seconds" value from the error detail,
// or 0 when the message carries no such hint.
func extractRetryAfter(body []byte) int {
	match := retryAfterRegex.FindStringSubmatch(extractErrorDetail(body))
	if len(match) >= 2 {
		if n, err := strconv.Atoi(match[1]); err == nil && n > 0 {
			return n
		}
	}
	return 0
}

// isDuplicateReport reports whether a 429 detail is AbuseIPDB's per-IP
// 15-minute duplicate rejection rather than an account rate limit.
func isDuplicateReport(detail string) bool {
	return strings.Contains(strings.ToLower(detail), "same ip address")
}

func extractErrorDetail(body []byte) string {
	var result struct {
		Errors []struct {
			Detail string `json:"detail"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(body, &result); err == nil && len(result.Errors) > 0 {
		return result.Errors[0].Detail
	}
	return "no detail"
}
