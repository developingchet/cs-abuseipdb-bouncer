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
	New: func() any { return bytes.NewBuffer(make([]byte, 0, 4096)) },
}

const (
	defaultReportURL = "https://api.abuseipdb.com/api/v2/report"
	defaultCheckURL  = "https://api.abuseipdb.com/api/v2/check"
	reportTimeout    = 15 * time.Second
	checkTimeout     = 10 * time.Second
	maxRetries       = 3
	initialBackoff   = 5 * time.Second
)

// ClientConfig holds configuration for the AbuseIPDB client.
type ClientConfig struct {
	APIKey    string
	Precheck  bool
	ReportURL string // Override for testing
	CheckURL  string // Override for testing
}

// Client implements the sink.Sink interface for AbuseIPDB.
type Client struct {
	apiKey     string
	precheck   bool
	reportURL  string
	checkURL   string
	httpClient *http.Client
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
			log.Debug().Err(err).Str("ip", ip).Msg("precheck error, proceeding with report")
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
	backoff := initialBackoff

	for attempt := 1; attempt <= maxRetries; attempt++ {
		code, body, err := c.doReport(ctx, ip, categories, comment)
		if err != nil {
			// Distinguish context deadline exceeded from other network errors.
			if ctx.Err() != nil {
				metrics.APIErrors.WithLabelValues("timeout").Inc()
				return ctx.Err()
			}
			metrics.APIErrors.WithLabelValues("network").Inc()
			if attempt < maxRetries {
				log.Warn().
					Int("attempt", attempt).
					Int("max", maxRetries).
					Dur("wait", backoff).
					Str("ip", ip).
					Msg("retry")
				select {
				case <-time.After(backoff):
				case <-ctx.Done():
					return ctx.Err()
				}
				backoff *= 2
				continue
			}
			return fmt.Errorf("all %d attempts failed for ip=%s: %w", maxRetries, ip, err)
		}

		switch code {
		case http.StatusOK:
			return nil

		case 422:
			detail := extractErrorDetail(body)
			log.Debug().Str("ip", ip).Str("detail", detail).Msg("skip duplicate/invalid")
			return nil // Not an error; the IP was already reported or is whitelisted

		case http.StatusTooManyRequests:
			metrics.APIErrors.WithLabelValues("rate_limit").Inc()
			waitSec := extractRetryAfter(body)
			log.Warn().
				Int("sleep", waitSec).
				Msg("rate-limited -- check daily quota at abuseipdb.com/account")
			select {
			case <-time.After(time.Duration(waitSec) * time.Second):
			case <-ctx.Done():
				return ctx.Err()
			}
			return fmt.Errorf("rate limited for ip=%s", ip)

		case http.StatusUnauthorized:
			metrics.APIErrors.WithLabelValues("auth").Inc()
			log.Error().Msg("401 unauthorized -- verify ABUSEIPDB_API_KEY")
			return fmt.Errorf("unauthorized (401)")

		default:
			log.Warn().Int("http", code).Str("ip", ip).Msg("unexpected response")
			if attempt < maxRetries {
				log.Warn().
					Int("attempt", attempt).
					Int("max", maxRetries).
					Dur("wait", backoff).
					Str("ip", ip).
					Msg("retry")
				select {
				case <-time.After(backoff):
				case <-ctx.Done():
					return ctx.Err()
				}
				backoff *= 2
				continue
			}
			return fmt.Errorf("unexpected http %d for ip=%s", code, ip)
		}
	}

	return fmt.Errorf("all %d attempts exhausted for ip=%s", maxRetries, ip)
}

func (c *Client) doReport(ctx context.Context, ip, categories, comment string) (int, []byte, error) {
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
		return 0, nil, err
	}

	req.Header.Set("Key", c.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	buf := respBufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer respBufPool.Put(buf)
	_, _ = io.Copy(buf, io.LimitReader(resp.Body, 4096))
	body := make([]byte, buf.Len())
	copy(body, buf.Bytes())
	return resp.StatusCode, body, nil
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

	buf := respBufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer respBufPool.Put(buf)
	_, _ = io.Copy(buf, io.LimitReader(resp.Body, 4096))
	body := make([]byte, buf.Len())
	copy(body, buf.Bytes())

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

// Healthy checks API reachability (does not consume quota).
func (c *Client) Healthy(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.checkURL+"?ipAddress=127.0.0.1&maxAgeInDays=1", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Key", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("abuseipdb unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("abuseipdb: invalid API key (401)")
	}
	return nil
}

func (c *Client) Close() error { return nil }

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

// retryAfterRegex extracts the seconds from AbuseIPDB rate-limit messages such as
// "Try again in 42 seconds." Matching on "in N second" avoids false-positives
// from other numbers in the message (e.g. "rate limit of 1000 requests").
var retryAfterRegex = regexp.MustCompile(`\bin\s+(\d+)\s+second`)

func extractRetryAfter(body []byte) int {
	detail := extractErrorDetail(body)
	match := retryAfterRegex.FindStringSubmatch(detail)
	if len(match) >= 2 {
		if n, err := strconv.Atoi(match[1]); err == nil && n > 0 {
			return n
		}
	}
	return 60
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
