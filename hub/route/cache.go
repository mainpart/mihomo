package route

import (
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

func cacheRouter() http.Handler {
	r := chi.NewRouter()
	r.Post("/fakeip/flush", flushFakeIPPool)
	r.Post("/dns/flush", flushDnsCache)
	return r
}

func flushFakeIPPool(w http.ResponseWriter, r *http.Request) {
	err := resolver.FlushFakeIP()
	if err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError(err.Error()))
		return
	}
	render.NoContent(w, r)
}

func flushDnsCache(w http.ResponseWriter, r *http.Request) {
	resolver.ClearCache()
	for _, proxy := range tunnel.Proxies() {
		clearProxyDNSCache(proxy)
	}
	for _, provider := range tunnel.Providers() {
		for _, proxy := range provider.Proxies() {
			clearProxyDNSCache(proxy)
		}
	}
	render.NoContent(w, r)
}

func clearProxyDNSCache(proxy C.Proxy) {
	if clearer, ok := proxy.Adapter().(interface{ ClearDNSCache() }); ok {
		clearer.ClearDNSCache()
	}
}
