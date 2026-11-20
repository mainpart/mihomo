package route

import (
	"testing"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
)

type cacheTestAdapter struct {
	outbound.ProxyAdapter
	cleared bool
}

func (a *cacheTestAdapter) ClearDNSCache() { a.cleared = true }

func TestClearProxyDNSCache(t *testing.T) {
	a := &cacheTestAdapter{}
	clearProxyDNSCache(adapter.NewProxy(outbound.NewAutoCloseProxyAdapter(&outbound.SingMux{ProxyAdapter: a})))
	if !a.cleared {
		t.Fatal("outbound DNS cache was not cleared")
	}
}
