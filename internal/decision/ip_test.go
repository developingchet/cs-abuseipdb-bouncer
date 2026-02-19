package decision

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestWhitelistFilter(t *testing.T) {
	tests := []struct {
		input    string
		prefixes []netip.Prefix
		skip     bool
		matching string // matching prefix string expected in Detail (skip cases only)
		reason   string
	}{
		{
			input:    "203.0.113.42",
			prefixes: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
			skip:     true,
			matching: "203.0.113.0/24",
			reason:   "IP inside CIDR range",
		},
		{
			input:    "203.0.113.255",
			prefixes: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
			skip:     true,
			matching: "203.0.113.0/24",
			reason:   "IP at CIDR boundary",
		},
		{
			input:    "203.0.114.1",
			prefixes: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
			skip:     false,
			reason:   "IP just outside CIDR",
		},
		{
			input:    "198.51.100.7",
			prefixes: []netip.Prefix{netip.MustParsePrefix("198.51.100.7/32")},
			skip:     true,
			matching: "198.51.100.7/32",
			reason:   "Exact single-IP prefix",
		},
		{
			input:    "2001:db8::1",
			prefixes: []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")},
			skip:     true,
			matching: "2001:db8::/32",
			reason:   "IPv6 address in range",
		},
		{
			input:    "::ffff:203.0.113.42",
			prefixes: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
			skip:     true,
			matching: "203.0.113.0/24",
			reason:   "IPv4-in-IPv6 form",
		},
		{
			input:    "203.0.113.42/32",
			prefixes: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
			skip:     true,
			matching: "203.0.113.0/24",
			reason:   "Decision value with CIDR notation",
		},
		{
			input:    "not-an-ip",
			prefixes: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
			skip:     false,
			reason:   "Invalid decision IP",
		},
		{
			input:    "203.0.113.42",
			prefixes: []netip.Prefix{},
			skip:     false,
			reason:   "Empty prefix list",
		},
		{
			input: "10.0.0.1",
			prefixes: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/8"),
				netip.MustParsePrefix("192.168.0.0/16"),
			},
			skip:     true,
			matching: "10.0.0.0/8",
			reason:   "Multiple prefixes, first matches",
		},
		{
			input: "192.168.1.1",
			prefixes: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/8"),
				netip.MustParsePrefix("192.168.0.0/16"),
			},
			skip:     true,
			matching: "192.168.0.0/16",
			reason:   "Multiple prefixes, second matches",
		},
		{
			input:    "8.8.8.8",
			prefixes: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")},
			skip:     false,
			reason:   "No prefix matches",
		},
	}

	for _, tt := range tests {
		t.Run(tt.reason, func(t *testing.T) {
			dec := &Decision{Value: tt.input}
			f := WhitelistFilter(tt.prefixes)
			result := f(dec)
			if tt.skip {
				require.NotNil(t, result, "expected decision to be skipped")
				assert.Equal(t, "whitelist", result.Filter)
				assert.Contains(t, result.Detail, tt.input)
				assert.Contains(t, result.Detail, tt.matching)
			} else {
				assert.Nil(t, result, "expected decision to pass")
			}
		})
	}
}
