package config_test

import (
	"fmt"
	"testing"

	"github.com/metacubex/mihomo/config"
	_ "github.com/metacubex/mihomo/hub/executor"
)

func TestSocksResolverDNSYAML(t *testing.T) {
	for _, tc := range []struct {
		field   string
		wantErr bool
	}{
		{"", false},
		{"resolver-dns: null", true},
		{"resolver_dns: null", true},
		{"resolver-dns: []", true},
		{"resolver-dns: 10.0.0.1", true},
		{"resolver-dns: [10.0.0.1, null]", true},
		{"resolver-dns: [10.0.0.1, 10.0.0.2]", false},
	} {
		t.Run(tc.field, func(t *testing.T) {
			input := fmt.Sprintf("proxies:\n  - name: corp\n    type: socks5\n    server: 127.0.0.1\n    port: 1080\n    udp: true\n    %s\nrules:\n  - MATCH,DIRECT\n", tc.field)
			_, err := config.Parse([]byte(input))
			if (err != nil) != tc.wantErr {
				t.Fatalf("Parse error = %v", err)
			}
		})
	}
}
