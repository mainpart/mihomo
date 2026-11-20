package config_test

import (
	"fmt"
	"testing"

	"github.com/metacubex/mihomo/config"
	_ "github.com/metacubex/mihomo/hub/executor"
)

func TestRealityClientVersionYAML(t *testing.T) {
	for _, tc := range []struct {
		version string
		wantErr bool
	}{
		{"26.3.27", false},
		{"26.3.256", true},
	} {
		t.Run(tc.version, func(t *testing.T) {
			input := fmt.Sprintf(`proxies:
  - name: test
    type: vless
    server: example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000001
    tls: true
    client-fingerprint: chrome
    reality-opts:
      public-key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
      client-version: "%s"
rules:
  - MATCH,DIRECT
`, tc.version)
			_, err := config.Parse([]byte(input))
			if (err != nil) != tc.wantErr {
				t.Fatalf("Parse error = %v", err)
			}
		})
	}
}
