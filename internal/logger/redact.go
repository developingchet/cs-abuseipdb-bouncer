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

type RedactWriter struct{ w io.Writer }

func NewRedactWriter(w io.Writer) *RedactWriter { return &RedactWriter{w: w} }

func (r *RedactWriter) Write(p []byte) (int, error) {
	out := p
	for _, pat := range redactPatterns {
		out = pat.re.ReplaceAllLiteral(out, pat.replacement)
	}
	_, err := r.w.Write(out)
	return len(p), err
}
