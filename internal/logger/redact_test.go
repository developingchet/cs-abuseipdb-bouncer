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
