package decision

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsPrivate(t *testing.T) {
	tests := []struct {
		ip       string
		expected bool
		reason   string
	}{
		// RFC1918 Class A (10.0.0.0/8)
		{"10.0.0.1", true, "RFC1918 Class A start"},
		{"10.255.255.255", true, "RFC1918 Class A end"},
		{"10.100.50.25", true, "RFC1918 Class A middle"},

		// RFC1918 Class B (172.16.0.0/12)
		{"172.16.0.1", true, "RFC1918 Class B start"},
		{"172.31.255.255", true, "RFC1918 Class B end"},
		{"172.20.10.5", true, "RFC1918 Class B middle"},
		{"172.15.255.255", false, "just below RFC1918 Class B"},
		{"172.32.0.0", false, "just above RFC1918 Class B"},

		// RFC1918 Class C (192.168.0.0/16)
		{"192.168.0.1", true, "RFC1918 Class C start"},
		{"192.168.255.255", true, "RFC1918 Class C end"},
		{"192.168.1.100", true, "RFC1918 Class C middle"},

		// Loopback (127.0.0.0/8)
		{"127.0.0.1", true, "loopback standard"},
		{"127.255.255.255", true, "loopback end"},

		// Link-local (169.254.0.0/16)
		{"169.254.0.1", true, "link-local start"},
		{"169.254.255.255", true, "link-local end"},
		{"169.253.255.255", false, "just below link-local"},

		// This network (0.0.0.0/8)
		{"0.0.0.0", true, "this network start"},
		{"0.255.255.255", true, "this network end"},

		// CGNAT (100.64.0.0/10)
		{"100.64.0.1", true, "CGNAT start"},
		{"100.127.255.255", true, "CGNAT end"},
		{"100.100.0.1", true, "CGNAT middle"},
		{"100.63.255.255", false, "just below CGNAT"},
		{"100.128.0.0", false, "just above CGNAT"},

		// IPv6 loopback
		{"::1", true, "IPv6 loopback"},

		// IPv6 link-local (fe80::/10)
		{"fe80::1", true, "IPv6 link-local"},
		{"fe80::abcd:1234:5678", true, "IPv6 link-local full"},

		// IPv6 unique local (fc00::/7)
		{"fc00::1", true, "IPv6 unique local fc00"},
		{"fd00::1", true, "IPv6 unique local fd00"},
		{"fdab::1234", true, "IPv6 unique local fdab"},

		// Public IPs (should NOT be private)
		{"8.8.8.8", false, "Google DNS"},
		{"1.1.1.1", false, "Cloudflare DNS"},
		{"203.0.113.42", false, "TEST-NET-3 (public)"},
		{"198.51.100.1", false, "TEST-NET-2 (public)"},
		{"93.184.216.34", false, "example.com"},

		// Public IPv6
		{"2001:db8::1", false, "IPv6 documentation prefix"},
		{"2606:4700::1", false, "Cloudflare IPv6"},

		// CIDR notation (should strip prefix)
		{"192.168.1.0/24", true, "private with CIDR"},
		{"8.8.8.0/24", false, "public with CIDR"},

		// Invalid input
		{"not-an-ip", false, "invalid IP returns false"},
		{"", false, "empty string returns false"},
	}

	for _, tt := range tests {
		t.Run(tt.reason, func(t *testing.T) {
			result := IsPrivate(tt.ip)
			assert.Equal(t, tt.expected, result, "IsPrivate(%q) = %v, want %v (%s)",
				tt.ip, result, tt.expected, tt.reason)
		})
	}
}
