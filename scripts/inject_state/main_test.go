// Package main — unit tests for inject_state helper functions.
//
// inject_state is a development tool, not part of the production bouncer.
// Its main() function requires a real bbolt database and cannot be tested
// here, but the two pure helper functions — sanitizeIP and utcDateString —
// are fully testable and cover all the normalization logic the tool depends on.
package main

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

// ── sanitizeIP ────────────────────────────────────────────────────────────────

func TestSanitizeIP_IPv4_Unchanged(t *testing.T) {
	assert.Equal(t, "203.0.113.42", sanitizeIP("203.0.113.42"))
}

func TestSanitizeIP_IPv4_CIDR_Stripped(t *testing.T) {
	assert.Equal(t, "203.0.113.0", sanitizeIP("203.0.113.0/24"))
}

func TestSanitizeIP_IPv6_ColonsReplacedWithUnderscores(t *testing.T) {
	result := sanitizeIP("2001:db8::1")
	assert.NotContains(t, result, ":",
		"IPv6 colons must be replaced with underscores so the key is bbolt-safe")
	assert.Contains(t, result, "_")
}

func TestSanitizeIP_IPv6_CIDR_StrippedAndColonsReplaced(t *testing.T) {
	result := sanitizeIP("2001:db8::/32")
	assert.NotContains(t, result, ":", "colons must be removed")
	assert.NotContains(t, result, "/", "CIDR suffix must be stripped")
}

func TestSanitizeIP_IPv4MappedIPv6_ColonsReplaced(t *testing.T) {
	// ::ffff:203.0.113.42 is an IPv4-mapped IPv6 address. netip.ParseAddr
	// keeps it in mapped form (does NOT unmap to plain IPv4), so String()
	// returns "::ffff:203.0.113.42" and the colon-replacement step produces
	// a bbolt-safe key with no colons.
	result := sanitizeIP("::ffff:203.0.113.42")
	assert.NotContains(t, result, ":", "colons must be replaced with underscores")
	assert.NotContains(t, result, "/", "no CIDR suffix should remain")
	assert.Contains(t, result, "ffff", "mapped address indicator must be preserved")
}

// ── utcDateString ─────────────────────────────────────────────────────────────

func TestUtcDateString_MatchesYYYYMMDD(t *testing.T) {
	date := utcDateString()
	matched, err := regexp.MatchString(`^\d{4}-\d{2}-\d{2}$`, date)
	assert.NoError(t, err)
	assert.True(t, matched, "utcDateString must return YYYY-MM-DD format; got %q", date)
}
