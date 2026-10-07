// Copyright 2026 Arctel.net
// SPDX-License-Identifier: Apache-2.0

package nginx

import (
	"testing"

	lua "github.com/yuin/gopher-lua"
)

func TestSiteAuthRuntime(t *testing.T) {
	state := lua.NewState()
	t.Cleanup(state.Close)
	if err := state.DoString(`
package.preload["cjson.safe"] = function() return {encode = function(v) return "body" end, decode = function(v) return v end} end
package.preload["resty.random"] = function() return {bytes = function() return "random" end} end
package.preload["resty.sha256"] = function() return {new = function() return {update = function() end, final = function() return "hash" end} end} end
package.preload["resty.string"] = function() return {to_hex = function(v) return v end} end
ngx = {var = {}, header = {}, req = {}, location = {}, HTTP_POST = 8}
ngx.exit = function(status) ngx.status = status; return status end
ngx.redirect = function(url, status) ngx.status = status; ngx.redirect_url = url; return status end
ngx.encode_args = function() return "encoded" end
ngx.req.get_method = function() return ngx.method or "GET" end
ngx.req.get_uri_args = function() return ngx.args or {} end
ngx.location.capture = function(path, options)
    ngx.captured = path
    assert(options.method == ngx.HTTP_POST and options.body == "body")
    return {status = ngx.check_status or 200, body = {error_msg = "", data = {session = "session", return_path = "/private?x=1", max_age = 3600}}}
end
`); err != nil {
		t.Fatal(err)
	}
	if err := state.DoString("runtime = (function()\n" + siteAuthRuntimeLua + "\nend)()"); err != nil {
		t.Fatal(err)
	}
	if err := state.DoString(`
    local function reset()
    ngx.var = {scheme = "https", host = "app.example.com", uri = "/private", request_uri = "/private"}
    ngx.header = {}; ngx.status = nil; ngx.redirect_url = nil; ngx.captured = nil
    ngx.args = {}; ngx.method = "GET"; ngx.check_status = 200
end
reset(); runtime.check(1, "https://control.test")
assert(ngx.status == 302 and ngx.redirect_url:find("/api/v1/site%-auth/login"), "anonymous GET must redirect")
assert(ngx.header["Set-Cookie"]:find("Secure; HttpOnly; SameSite=Lax"), "challenge cookie must be secure")
reset(); ngx.method = "POST"; runtime.check(1, "https://control.test")
assert(ngx.status == 401, "anonymous POST must not redirect")
reset(); ngx.var.http_upgrade = "websocket"; runtime.check(1, "https://control.test")
assert(ngx.status == 401, "anonymous websocket must not redirect")
reset(); ngx.var.http_cookie = "__Host-openflare_site_1=valid; app=keep"; runtime.check(1, "https://control.test")
assert(ngx.status == nil and ngx.captured == "/openflare/site-auth/_check", "valid session must be checked")
assert(ngx.var.openflare_origin_cookie == "app=keep", "session cookie must not reach origin")
reset(); ngx.var.http_cookie = "__Host-openflare_site_1=valid"; ngx.check_status = 503; runtime.check(1, "https://control.test")
assert(ngx.status == 503, "control failure must fail closed")
reset(); ngx.var.http_cookie = "__Host-openflare_site_1=valid"; ngx.check_status = 403; runtime.check(1, "https://control.test")
assert(ngx.status == 403, "disabled source must fail closed")
reset(); ngx.var.uri = "/openflare/site-auth/_check"; runtime.check(1, "https://control.test")
assert(ngx.status == 404, "reserved endpoints must not reach origin")
reset(); ngx.var.uri = "/openflare/site-auth/complete"; ngx.args.ticket = "ticket"; runtime.check(1, "https://control.test")
assert(ngx.status == 400, "ticket without challenge must fail")
reset(); ngx.var.uri = "/openflare/site-auth/complete"; ngx.args.ticket = "ticket"; ngx.var.http_cookie = "__Host-openflare_challenge_1=challenge"; runtime.check(1, "https://control.test")
assert(ngx.status == 302 and ngx.redirect_url == "/private?x=1", "bound ticket must return to original path")
assert(ngx.captured == "/openflare/site-auth/_exchange" and #ngx.header["Set-Cookie"] == 2, "ticket must be exchanged once")
`); err != nil {
		t.Fatalf("site auth runtime security checks failed: %v", err)
	}
}
