package logger

import (
	"bytes"
	"testing"
)

func TestRedactWriter_Write(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Redact API Key",
			input:    "key: 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			expected: "key: [REDACTED-API-KEY]",
		},
		{
			name:     "Redact Bearer Token",
			input:    "Authorization: Bearer my.secret.token",
			expected: "Authorization: bearer [REDACTED]",
		},
		{
			name:     "Redact LAPI key header in a request dump",
			input:    "GET /v1/decisions/stream HTTP/1.1\r\nX-Api-Key: s3cr3t-lapi-key\r\n",
			expected: "GET /v1/decisions/stream HTTP/1.1\r\nX-Api-Key: [REDACTED]\r\n",
		},
		{
			name:     "Redact LAPI key header inside JSON string",
			input:    `{"message":"req: X-Api-Key: s3cr3t\r\nHost: x"}`,
			expected: `{"message":"req: X-Api-Key: [REDACTED]\r\nHost: x"}`,
		},
		{
			name:     "No Redaction Needed",
			input:    "Bouncer started successfully",
			expected: "Bouncer started successfully",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			rw := NewRedactWriter(&buf)

			n, err := rw.Write([]byte(tt.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if n != len(tt.input) {
				t.Errorf("expected length %d, got %d", len(tt.input), n)
			}
			if buf.String() != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, buf.String())
			}
		})
	}
}
