package decision

import (
	"fmt"
	"net/netip"
	"strings"
)

// Private and reserved IP ranges that should not be reported to AbuseIPDB.
// The RFC 5737 / RFC 3849 documentation ranges are deliberately not listed:
// they never appear in real traffic and the test suite uses them as stand-ins
// for public addresses.
var privateRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),     // RFC1918 Class A
	netip.MustParsePrefix("172.16.0.0/12"),  // RFC1918 Class B
	netip.MustParsePrefix("192.168.0.0/16"), // RFC1918 Class C
	netip.MustParsePrefix("127.0.0.0/8"),    // Loopback
	netip.MustParsePrefix("169.254.0.0/16"), // Link-local (RFC3927)
	netip.MustParsePrefix("0.0.0.0/8"),      // This network
	netip.MustParsePrefix("100.64.0.0/10"),  // CGNAT (RFC6598)
	netip.MustParsePrefix("192.0.0.0/24"),   // IETF protocol assignments (RFC6890)
	netip.MustParsePrefix("198.18.0.0/15"),  // Benchmarking (RFC2544)
	netip.MustParsePrefix("224.0.0.0/4"),    // Multicast
	netip.MustParsePrefix("240.0.0.0/4"),    // Reserved + limited broadcast
	netip.MustParsePrefix("::/128"),         // IPv6 unspecified
	netip.MustParsePrefix("::1/128"),        // IPv6 loopback
	netip.MustParsePrefix("fe80::/10"),      // IPv6 link-local
	netip.MustParsePrefix("fc00::/7"),       // IPv6 unique local (RFC4193)
	netip.MustParsePrefix("ff00::/8"),       // IPv6 multicast
}

// IsPrivate returns true if the IP address falls within a private or reserved range.
// Accepts bare IPs or CIDR notation (the prefix length is stripped before checking).
// IPv4-mapped IPv6 addresses (::ffff:a.b.c.d) are checked as IPv4.
func IsPrivate(ipStr string) bool {
	// Strip CIDR notation if present
	if idx := strings.IndexByte(ipStr, '/'); idx != -1 {
		ipStr = ipStr[:idx]
	}

	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return false
	}
	addr = addr.Unmap()

	for _, prefix := range privateRanges {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// WhitelistFilter returns a Filter that skips decisions whose IP falls within
// any of the provided prefixes. Call it conditionally (only when prefixes is
// non-empty) so the hot path has zero overhead when no whitelist is configured.
func WhitelistFilter(prefixes []netip.Prefix) Filter {
	return func(d *Decision) *SkipReason {
		ipStr := d.Value
		if idx := strings.IndexByte(ipStr, '/'); idx != -1 {
			ipStr = ipStr[:idx]
		}
		addr, err := netip.ParseAddr(ipStr)
		if err != nil {
			return nil // unparseable — let ValueRequired handle it
		}
		addr = addr.Unmap() // normalise IPv4-in-IPv6
		for _, pfx := range prefixes {
			if pfx.Contains(addr) {
				return &SkipReason{Filter: "whitelist", Detail: fmt.Sprintf("ip=%s matches %s", d.Value, pfx)}
			}
		}
		return nil
	}
}
