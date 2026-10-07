// Copyright 2026 Arctel.net
// SPDX-License-Identifier: Apache-2.0

package openresty

import (
	"fmt"
	"net/url"
	"strings"
)

func renderSiteAuth(config string, route Route) (string, error) {
	if route.OIDCAuthSourceID == nil {
		return config, nil
	}
	control, err := url.Parse(route.OIDCAuthURL)
	if err != nil || control.Scheme != "https" || control.Host == "" || control.User != nil || control.Path != "" || control.RawQuery != "" || control.Fragment != "" || strings.ContainsAny(route.OIDCAuthURL, "\r\n\"\\;{}$") || route.ID == 0 || !route.EnableHTTPS || !route.RedirectHTTP || route.BasicAuthEnabled {
		return "", fmt.Errorf("route %s has invalid OIDC configuration", route.SiteName)
	}
	// The normal renderer permits mixed HTTP-only/TLS domain partitions. OIDC
	// cannot: every bound domain must be protected, never an HTTP fallback.
	if len(route.DomainCertIDs) != len(normalizedRouteDomains(route)) {
		return "", fmt.Errorf("route %s OIDC requires certificates for every domain", route.SiteName)
	}
	for _, certID := range route.DomainCertIDs {
		if certID == 0 {
			return "", fmt.Errorf("route %s OIDC requires certificates for every domain", route.SiteName)
		}
	}
	// Server rewrite protects every location, including Pages API and static files,
	// without replacing the shared WAF/PoW/SW access directive.
	block := fmt.Sprintf(`    set $openflare_origin_cookie $http_cookie;
    rewrite_by_lua_block {
        if not ngx.is_subrequest then
            if not string.find(package.path, "%s/?.lua", 1, true) then
                package.path = "%s/?.lua;%s/?/init.lua;" .. package.path
            end
            require("site_auth.runtime").check(%d, %q)
        end
    }
    location = /openflare/site-auth/complete {
        access_log off;
        log_by_lua_block { }
        access_by_lua_block { }
        content_by_lua_block { ngx.exit(404) }
    }
    location = /openflare/site-auth/_check {
        internal;
        rewrite_by_lua_block { }
        access_by_lua_block { }
        access_log off;
        log_by_lua_block { }
        proxy_pass_request_headers off;
        proxy_set_header Host %s;
        proxy_set_header Content-Type application/json;
        proxy_ssl_server_name on;
        proxy_ssl_name %s;
        proxy_ssl_verify on;
        proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
        proxy_connect_timeout 3s;
        proxy_read_timeout 5s;
        proxy_cache off;
        proxy_pass %s/api/v1/site-auth/check;
    }
    location = /openflare/site-auth/_exchange {
        internal;
        rewrite_by_lua_block { }
        access_by_lua_block { }
        access_log off;
        log_by_lua_block { }
        proxy_pass_request_headers off;
        proxy_set_header Host %s;
        proxy_set_header Content-Type application/json;
        proxy_ssl_server_name on;
        proxy_ssl_name %s;
        proxy_ssl_verify on;
        proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;
        proxy_connect_timeout 3s;
        proxy_read_timeout 5s;
        proxy_cache off;
        proxy_pass %s/api/v1/site-auth/exchange;
    }
`, LuaDirPlaceholder, LuaDirPlaceholder, LuaDirPlaceholder, route.ID, route.OIDCAuthURL,
		control.Host, control.Hostname(), route.OIDCAuthURL, control.Host, control.Hostname(), route.OIDCAuthURL)
	config = strings.ReplaceAll(config, "        proxy_pass ", "        proxy_set_header Cookie $openflare_origin_cookie;\n        proxy_pass ")
	return strings.ReplaceAll(config, "server {\n    listen 443 ssl;\n", "server {\n    listen 443 ssl;\n"+block), nil
}
