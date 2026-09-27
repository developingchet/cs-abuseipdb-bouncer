package decision

import (
	"net/netip"
	"strconv"
	"testing"
)

// FuzzIsPrivate checks that no private, loopback, link-local, multicast or
// unspecified address is ever reported to AbuseIPDB, whether the decision
// carries it bare, as a CIDR or in IPv4-mapped IPv6 form.
func FuzzIsPrivate(f *testing.F) {
	f.Add([]byte{10, 0, 0, 1}, uint8(32))
	f.Add([]byte{192, 168, 1, 1}, uint8(24))
	f.Add([]byte{127, 0, 0, 1}, uint8(8))
	f.Add([]byte{224, 0, 0, 1}, uint8(4))
	f.Add([]byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, uint8(64))
	f.Add([]byte{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, uint8(128))
	f.Fuzz(func(t *testing.T, raw []byte, bits uint8) {
		addr, ok := netip.AddrFromSlice(raw)
		if !ok {
			return
		}
		addr = addr.Unmap()
		if !addr.IsPrivate() && !addr.IsLoopback() && !addr.IsLinkLocalUnicast() &&
			!addr.IsMulticast() && !addr.IsUnspecified() {
			return
		}
		length := int(bits) % (addr.BitLen() + 1)
		forms := []string{addr.String(), addr.String() + "/" + strconv.Itoa(length)}
		if addr.Is4() {
			forms = append(forms, netip.AddrFrom16(addr.As16()).String())
		}
		for _, form := range forms {
			if !IsPrivate(form) {
				t.Fatalf("IsPrivate(%q) = false for non-public address %s", form, addr)
			}
		}
	})
}
