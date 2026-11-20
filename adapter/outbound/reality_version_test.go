package outbound

import (
	"encoding/base64"
	"testing"
)

func TestRealityClientVersion(t *testing.T) {
	key := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	for _, tc := range []struct {
		input string
		want  [3]byte
		bad   bool
	}{
		{"", [3]byte{1, 8, 2}, false},
		{"26.3.27", [3]byte{26, 3, 27}, false},
		{"26.3", [3]byte{}, true},
		{"26.3.256", [3]byte{}, true},
		{"26.-1.27", [3]byte{}, true},
	} {
		t.Run(tc.input, func(t *testing.T) {
			config, err := (RealityOptions{PublicKey: key, ClientVersion: tc.input}).Parse()
			if tc.bad {
				if err == nil {
					t.Fatal("expected invalid client version error")
				}
				return
			}
			if err != nil || config.ClientVersion != tc.want {
				t.Fatalf("version: got %v, error %v; want %v", config, err, tc.want)
			}
		})
	}
}
