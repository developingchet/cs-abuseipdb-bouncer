package abuseipdb

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/developingchet/cs-abuseipdb-bouncer/internal/sink"
)

// buildClient creates a Client wired to the given test server URLs.
func buildClient(reportURL, checkURL string) *Client {
	return NewClient(ClientConfig{
		APIKey:    "test-key",
		Precheck:  false,
		ReportURL: reportURL,
		CheckURL:  checkURL,
	})
}

func TestReport_Success(t *testing.T) {
	var received url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "test-key", r.Header.Get("Key"))
		require.Equal(t, "application/json", r.Header.Get("Accept"))
		require.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

		require.NoError(t, r.ParseForm())
		received = r.Form

		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"data":{"abuseConfidenceScore":0}}`)
	}))
	defer srv.Close()

	c := buildClient(srv.URL, srv.URL)
	err := c.Report(context.Background(), &sink.Report{
		IP:         "203.0.113.42",
		DecisionID: 99,
		Scenario:   "crowdsecurity/ssh-bf",
	})

	require.NoError(t, err)
	assert.Equal(t, "203.0.113.42", received.Get("ip"))
	assert.Equal(t, "22,18", received.Get("categories"))
	assert.Equal(t, "CrowdSec detection | scenario: ssh-bf", received.Get("comment"))
}

func TestReport_Duplicate422(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(422)
		fmt.Fprint(w, `{"errors":[{"detail":"Duplicate report within last 15 minutes"}]}`)
	}))
	defer srv.Close()

	c := buildClient(srv.URL, srv.URL)
	err := c.Report(context.Background(), &sink.Report{IP: "203.0.113.42", Scenario: "crowdsecurity/ssh-bf"})
	// 422 is not an error -- duplicate report is silently accepted
	assert.NoError(t, err)
}

func TestReport_Unauthorized401(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"errors":[{"detail":"Authentication failed."}]}`)
	}))
	defer srv.Close()

	c := buildClient(srv.URL, srv.URL)
	err := c.Report(context.Background(), &sink.Report{IP: "203.0.113.42", Scenario: "crowdsecurity/ssh-bf"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "401")
	// Must not retry on 401
	assert.Equal(t, 1, calls)
}

func TestReport_RateLimit429(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, `{"errors":[{"detail":"Daily rate limit of 1000 requests exceeded for this user on endpoint '/api/v2/report'. Try again in 1 seconds."}]}`)
	}))
	defer srv.Close()

	c := buildClient(srv.URL, srv.URL)
	// Set a very short timeout so the wait extracted from the body (1s) is bounded.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := c.Report(ctx, &sink.Report{IP: "203.0.113.42", Scenario: "crowdsecurity/ssh-bf"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "rate limited")
	// 429 should not retry -- fails immediately after sleeping Retry-After duration
	assert.Equal(t, 1, calls)
}

func TestReport_NetworkError_Retries(t *testing.T) {
	// Point at a URL that will refuse connections.
	c := buildClient("http://127.0.0.1:1", "http://127.0.0.1:1")
	start := time.Now()
	err := c.Report(context.Background(), &sink.Report{IP: "203.0.113.42", Scenario: "crowdsecurity/ssh-bf"})
	elapsed := time.Since(start)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "attempts")
	// With 3 attempts and 5s+10s backoff the total wait should be at least 5 seconds.
	// We verify at least 1 retry happened (backoff > 0).
	assert.GreaterOrEqual(t, elapsed, time.Second)
}

func TestReport_UnexpectedStatus_Retries(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"errors":[{"detail":"internal server error"}]}`)
	}))
	defer srv.Close()

	// The initial retry backoff is 5s. A 2s context expires during the first
	// backoff wait, so only one attempt is made before the context cancels.
	// The important property being tested is that a 5xx response returns an error.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	c := buildClient(srv.URL, srv.URL)
	err := c.Report(ctx, &sink.Report{IP: "203.0.113.42", Scenario: "crowdsecurity/ssh-bf"})
	assert.Error(t, err)
	assert.GreaterOrEqual(t, calls, 1)
}

// TestReport_5xx_ExhaustsAllRetries verifies that the client makes exactly
// maxRetries attempts before giving up on persistent 5xx responses.
// NOTE: this test takes ~15 s (5 s + 10 s retry backoffs) — same as the
// network-error retry test. It is not marked short because slow test
// precedent is already set by TestReport_NetworkError_Retries.
func TestReport_5xx_ExhaustsAllRetries(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprint(w, `{"errors":[{"detail":"service temporarily unavailable"}]}`)
	}))
	defer srv.Close()

	// No context timeout: allow all three attempts plus the two backoff sleeps.
	c := buildClient(srv.URL, srv.URL)
	err := c.Report(context.Background(), &sink.Report{IP: "203.0.113.42", Scenario: "crowdsecurity/ssh-bf"})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "503",
		"final error must identify the HTTP status code")
	assert.Equal(t, maxRetries, calls,
		"client must attempt exactly maxRetries times before giving up on 5xx")
}

func TestReport_ContextCancelled(t *testing.T) {
	// The handler sleeps longer than the client context so the request is
	// always aborted by context cancellation. CloseClientConnections() is
	// called before Close() to force-close any lingering TCP connections;
	// without this, srv.Close() can block indefinitely on Windows waiting
	// for the server-side connection goroutine to notice the client disconnect.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer func() {
		srv.CloseClientConnections()
		srv.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	c := buildClient(srv.URL, srv.URL)
	err := c.Report(ctx, &sink.Report{IP: "203.0.113.42", Scenario: "crowdsecurity/ssh-bf"})
	assert.Error(t, err)
}

func TestReport_WithPrecheck_Whitelisted(t *testing.T) {
	checkCalled := false
	reportCalled := false

	mux := http.NewServeMux()
	mux.HandleFunc("/check", func(w http.ResponseWriter, r *http.Request) {
		checkCalled = true
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"data":{"isWhitelisted":true}}`)
	})
	mux.HandleFunc("/report", func(w http.ResponseWriter, r *http.Request) {
		reportCalled = true
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"data":{}}`)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClient(ClientConfig{
		APIKey:    "test-key",
		Precheck:  true,
		ReportURL: srv.URL + "/report",
		CheckURL:  srv.URL + "/check",
	})

	err := c.Report(context.Background(), &sink.Report{IP: "203.0.113.42", Scenario: "crowdsecurity/ssh-bf"})
	require.NoError(t, err)
	assert.True(t, checkCalled)
	assert.False(t, reportCalled, "should not report whitelisted IPs")
}

func TestReport_WithPrecheck_NotWhitelisted(t *testing.T) {
	reportCalled := false

	mux := http.NewServeMux()
	mux.HandleFunc("/check", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"data":{"isWhitelisted":false}}`)
	})
	mux.HandleFunc("/report", func(w http.ResponseWriter, r *http.Request) {
		reportCalled = true
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"data":{}}`)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClient(ClientConfig{
		APIKey:    "test-key",
		Precheck:  true,
		ReportURL: srv.URL + "/report",
		CheckURL:  srv.URL + "/check",
	})

	err := c.Report(context.Background(), &sink.Report{IP: "203.0.113.42", Scenario: "crowdsecurity/ssh-bf"})
	require.NoError(t, err)
	assert.True(t, reportCalled, "should report non-whitelisted IPs")
}

func TestReport_WithPrecheck_CheckError_Proceeds(t *testing.T) {
	reportCalled := false

	mux := http.NewServeMux()
	mux.HandleFunc("/check", func(w http.ResponseWriter, r *http.Request) {
		// Return invalid JSON to trigger an unmarshal error.
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `not json`)
	})
	mux.HandleFunc("/report", func(w http.ResponseWriter, r *http.Request) {
		reportCalled = true
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"data":{}}`)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := NewClient(ClientConfig{
		APIKey:    "test-key",
		Precheck:  true,
		ReportURL: srv.URL + "/report",
		CheckURL:  srv.URL + "/check",
	})

	// Check errors should be silently ignored and the report should proceed.
	err := c.Report(context.Background(), &sink.Report{IP: "203.0.113.42", Scenario: "crowdsecurity/ssh-bf"})
	require.NoError(t, err)
	assert.True(t, reportCalled, "should proceed with report when precheck fails")
}

func TestReport_StripsCIDR(t *testing.T) {
	var receivedIP string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		receivedIP = r.FormValue("ip")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"data":{}}`)
	}))
	defer srv.Close()

	c := buildClient(srv.URL, srv.URL)
	// Value may arrive with CIDR suffix from CrowdSec LAPI.
	err := c.Report(context.Background(), &sink.Report{IP: "203.0.113.42/32", Scenario: "crowdsecurity/ssh-bf"})
	require.NoError(t, err)
	assert.Equal(t, "203.0.113.42", receivedIP)
}

func TestHealthy_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "test-key", r.Header.Get("Key"))
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"data":{"isWhitelisted":false}}`)
	}))
	defer srv.Close()

	c := buildClient(srv.URL, srv.URL)
	assert.NoError(t, c.Healthy(context.Background()))
}

func TestHealthy_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := buildClient(srv.URL, srv.URL)
	err := c.Healthy(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid API key")
}

func TestExtractRetryAfter(t *testing.T) {
	tests := []struct {
		body     string
		expected int
	}{
		{`{"errors":[{"detail":"Daily rate limit of 1000 requests exceeded. Try again in 42 seconds."}]}`, 42},
		{`{"errors":[{"detail":"Rate limit exceeded"}]}`, 60}, // no number -- use default
		{`not json`, 60},
		{`{"errors":[{"detail":"Try again in 0 seconds."}]}`, 60}, // zero -- use default
	}

	for _, tt := range tests {
		got := extractRetryAfter([]byte(tt.body))
		assert.Equal(t, tt.expected, got, "body=%s", tt.body)
	}
}

func TestExtractErrorDetail(t *testing.T) {
	body := `{"errors":[{"detail":"Duplicate report within last 15 minutes"}]}`
	assert.Equal(t, "Duplicate report within last 15 minutes", extractErrorDetail([]byte(body)))

	assert.Equal(t, "no detail", extractErrorDetail([]byte(`{}`)))
	assert.Equal(t, "no detail", extractErrorDetail([]byte(`not json`)))
}

func TestStripCIDR(t *testing.T) {
	assert.Equal(t, "203.0.113.42", stripCIDR("203.0.113.42/32"))
	assert.Equal(t, "203.0.113.42", stripCIDR("203.0.113.42"))
	assert.Equal(t, "2001:db8::1", stripCIDR("2001:db8::1/128"))
}

func TestStripAuthor(t *testing.T) {
	assert.Equal(t, "ssh-bf", stripAuthor("crowdsecurity/ssh-bf"))
	assert.Equal(t, "ssh-bf", stripAuthor("ssh-bf"))
	assert.Equal(t, "my-scenario", stripAuthor("myorg/sub/my-scenario"))
}

func TestFormatCategories(t *testing.T) {
	assert.Equal(t, "22,18", formatCategories([]int{22, 18}))
	assert.Equal(t, "15", formatCategories([]int{15}))
	assert.Equal(t, "", formatCategories([]int{}))
}

// TestRequestBodyFormat verifies the exact wire format expected by AbuseIPDB.
func TestRequestBodyFormat(t *testing.T) {
	var vals url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		vals = r.Form
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"data":{}}`)
	}))
	defer srv.Close()

	c := buildClient(srv.URL, srv.URL)
	_ = c.Report(context.Background(), &sink.Report{IP: "1.2.3.4", Scenario: "crowdsecurity/http-probing"})

	assert.Equal(t, "1.2.3.4", vals.Get("ip"))
	assert.NotEmpty(t, vals.Get("categories"))
	assert.Contains(t, vals.Get("comment"), "http-probing")
}

// TestReport_CommentFormat checks the comment does not include the author prefix.
func TestReport_CommentFormat(t *testing.T) {
	var comment string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		comment = r.FormValue("comment")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{}})
	}))
	defer srv.Close()

	c := buildClient(srv.URL, srv.URL)
	_ = c.Report(context.Background(), &sink.Report{IP: "1.2.3.4", Scenario: "crowdsecurity/ssh-bf"})

	assert.Equal(t, "CrowdSec detection | scenario: ssh-bf", comment)
}
