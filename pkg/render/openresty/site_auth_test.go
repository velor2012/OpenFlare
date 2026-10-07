// Copyright 2026 Arctel.net
// SPDX-License-Identifier: Apache-2.0

package openresty

import (
	"strings"
	"testing"
)

func TestRenderSiteAuth(t *testing.T) {
	id := uint64(1)
	route := Route{ID: 1, SiteName: "private", Domains: []string{"app.example.com"}, DomainCertIDs: []uint{1}, EnableHTTPS: true, RedirectHTTP: true, OIDCAuthSourceID: &id, OIDCAuthURL: "https://control.example.com"}
	config := renderHTTPSServer("app.example.com", "private", "http://origin.test", "", 1, nil, routeCacheConfig{}, routeLimitConfig{}, routeUpstreamConfig{}, true, true, false, "", "", true, ConfigSnapshot{})
	got, err := renderSiteAuth(config, route)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"site_auth.runtime", "ngx.is_subrequest", "internal;", "proxy_pass_request_headers off;", "proxy_ssl_verify on;", "https://control.example.com/api/v1/site-auth/check", "waf.runtime", "pow.runtime", "sw.runtime"} {
		if !strings.Contains(got, required) {
			t.Errorf("renderSiteAuth() missing %q", required)
		}
	}
	if strings.Count(got, "access_by_lua_block") != 4 {
		t.Errorf("renderSiteAuth() access blocks = %d, want one shared and three isolated auth locations", strings.Count(got, "access_by_lua_block"))
	}
	pages := renderHTTPSPagesServer("app.example.com", "private", 1, &PagesDeployment{APIProxyEnabled: true, APIProxyPath: "/api", APIProxyPass: "http://origin.test"}, routeLimitConfig{}, false, true, false, "", "", false, ConfigSnapshot{})
	if got, err := renderSiteAuth(pages, route); err != nil || !strings.Contains(got, "site_auth.runtime") || !strings.Contains(got, "location /api") {
		t.Errorf("renderSiteAuth(pages) = %v, want protected Pages and API locations", err)
	}
	route.EnableHTTPS = false
	if _, err := renderSiteAuth(config, route); err == nil {
		t.Error("renderSiteAuth(HTTP) accepted, want rejected")
	}
	route.EnableHTTPS = true
	route.DomainCertIDs = []uint{0}
	if _, err := renderSiteAuth(config, route); err == nil {
		t.Error("renderSiteAuth(HTTP-only domain) accepted, want rejected")
	}
	route.DomainCertIDs = []uint{1}
	route.OIDCAuthURL = "https://control.example.com;\nreturn 200;"
	if _, err := renderSiteAuth(config, route); err == nil {
		t.Error("renderSiteAuth(injected URL) accepted, want rejected")
	}
	if got, err := renderSiteAuth(config, Route{}); err != nil || got != config {
		t.Errorf("renderSiteAuth(no OIDC) changed existing config, want unchanged")
	}
}
