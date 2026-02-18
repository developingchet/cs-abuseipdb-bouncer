// Package logger provides log output helpers, including a secret-masking writer.
package logger

import (
	"io"
	"regexp"
)

var redactPatterns = []struct {
	re          *regexp.Regexp
	replacement []byte
}{
	// AbuseIPDB API keys are 80 hex characters.
	{regexp.MustCompile(`[A-Fa-f0-9]{80}`), []byte("[REDACTED-API-KEY]")},
	// Bearer tokens in Authorization headers or log fields.
	{regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*`), []byte("bearer [REDACTED]")},
}

// RedactWriter wraps an io.Writer and replaces known secret patterns with
// redaction markers before forwarding the data downstream. It is safe for
// concurrent use only if the underlying writer is also safe.
type RedactWriter struct{ w io.Writer }

// NewRedactWriter returns a RedactWriter that redacts secrets before writing
// to w.
func NewRedactWriter(w io.Writer) *RedactWriter { return &RedactWriter{w: w} }

// Write redacts secrets in p and writes the result to the underlying writer.
// It always returns len(p), nil so that callers (e.g. zerolog) are not
// confused by a shorter-than-expected write.
func (r *RedactWriter) Write(p []byte) (int, error) {
	out := p
	for _, pat := range redactPatterns {
		out = pat.re.ReplaceAll(out, pat.replacement)
	}
	_, err := r.w.Write(out)
	return len(p), err
}
