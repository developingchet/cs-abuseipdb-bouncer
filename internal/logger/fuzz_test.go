package logger

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// FuzzRedactWriter checks that no 20-character run of an AbuseIPDB API key
// survives redaction, whatever text surrounds the key.
func FuzzRedactWriter(f *testing.F) {
	f.Add("api_key=", " status=200", []byte("0123456789abcdef0123456789abcdef01234567"))
	f.Add("", "", []byte{})
	f.Add("deadbeef", "cafe", []byte{0xff})
	f.Add("Authorization: Bearer ", "\n", []byte("k"))
	f.Fuzz(func(t *testing.T, before, after string, seed []byte) {
		key := hex.EncodeToString(bytes.Repeat(append(seed, 0x5a), 40))[:80]
		var out bytes.Buffer
		if _, err := NewRedactWriter(&out).Write([]byte(before + key + after)); err != nil {
			t.Fatal(err)
		}
		const window = 20
		for i := 0; i+window <= len(key); i++ {
			part := key[i : i+window]
			if strings.Contains(before+after, part) {
				continue
			}
			if strings.Contains(out.String(), part) {
				t.Fatalf("key fragment %q survives in %q", part, out.String())
			}
		}
	})
}
