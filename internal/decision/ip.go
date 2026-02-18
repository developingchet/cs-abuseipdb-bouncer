package decision

import (
	"net/netip"
	"strings"
)

// Private and reserved IP ranges that should not be reported to AbuseIPDB.
var privateRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),       // RFC1918 Class A
	netip.MustParsePrefix("172.16.0.0/12"),     // RFC1918 Class B
	netip.MustParsePrefix("192.168.0.0/16"),    // RFC1918 Class C
	netip.MustParsePrefix("127.0.0.0/8"),       // Loopback
	netip.MustParsePrefix("169.254.0.0/16"),    // Link-local (RFC3927)
	netip.MustParsePrefix("0.0.0.0/8"),         // This network
	netip.MustParsePrefix("100.64.0.0/10"),     // CGNAT (RFC6598)
	netip.MustParsePrefix("::1/128"),           // IPv6 loopback
	netip.MustParsePrefix("fe80::/10"),         // IPv6 link-local
	netip.MustParsePrefix("fc00::/7"),          // IPv6 unique local (RFC4193)
}

// IsPrivate returns true if the IP address falls within a private or reserved range.
// Accepts bare IPs or CIDR notation (the prefix length is stripped before checking).
func IsPrivate(ipStr string) bool {
	// Strip CIDR notation if present
	if idx := strings.IndexByte(ipStr, '/'); idx != -1 {
		ipStr = ipStr[:idx]
	}

	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return false
	}

	for _, prefix := range privateRanges {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
