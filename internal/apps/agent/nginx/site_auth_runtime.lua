local json = require("cjson.safe")
local random = require("resty.random")
local sha256 = require("resty.sha256")
local str = require("resty.string")
local M = {}
local prefix = "/openflare/site-auth/"

local function digest(value)
    local h = sha256:new()
    h:update(value)
    return str.to_hex(h:final())
end

local function cookie(name)
    local header = ngx.var.http_cookie or ""
    for key, value in header:gmatch("([^; =]+)=([^;]*)") do
        if key == name then return value end
    end
end

local function set_cookie(name, value, age)
    return name .. "=" .. value .. "; Path=/; Max-Age=" .. age .. "; Secure; HttpOnly; SameSite=Lax"
end

local function request(action, route_id, token, binding)
    local body = json.encode({route_id = route_id, host = ngx.var.host, token = token, binding = binding})
    local res = ngx.location.capture(prefix .. "_" .. action, {method = ngx.HTTP_POST, body = body})
    if not res then return nil, 503 end
    local envelope = json.decode(res.body)
    if res.status ~= 200 then
        return nil, res.status
    end
    if not envelope or envelope.error_msg ~= "" then return nil, 503 end
    return envelope.data, 200
end

function M.check(route_id, control)
    if ngx.var.scheme ~= "https" then return ngx.exit(403) end
    local session_name = "__Host-openflare_site_" .. route_id
    local challenge_name = "__Host-openflare_challenge_" .. route_id
    -- Never leak the reserved site-auth cookies to the upstream application.
    local origin_cookies = {}
    for key, value in (ngx.var.http_cookie or ""):gmatch("([^; =]+)=([^;]*)") do
        if key ~= session_name and key ~= challenge_name then
            origin_cookies[#origin_cookies + 1] = key .. "=" .. value
        end
    end
    if ngx.var.uri == prefix .. "complete" then
        ngx.header["Cache-Control"] = "no-store"
        ngx.header["Referrer-Policy"] = "no-referrer"
        local args = ngx.req.get_uri_args()
        local challenge = cookie(challenge_name)
        if ngx.req.get_method() ~= "GET" or type(args.ticket) ~= "string" or not challenge then return ngx.exit(400) end
        local data, status = request("exchange", route_id, args.ticket, digest(challenge))
        if status ~= 200 or type(data) ~= "table" or type(data.session) ~= "string" or type(data.return_path) ~= "string" or type(data.max_age) ~= "number" then
            return ngx.exit(status >= 500 and 503 or 401)
        end
        if not data.session:match("^[%w_-]+$") or data.return_path:sub(1, 1) ~= "/" or data.return_path:sub(1, 2) == "//" or data.return_path:find("[\r\n\\]") then return ngx.exit(503) end
        ngx.header["Set-Cookie"] = {set_cookie(session_name, data.session, data.max_age), set_cookie(challenge_name, "", 0)}
        return ngx.redirect(data.return_path, 302)
    end
    -- Reserved endpoints must never fall through to a protected origin.
    if ngx.var.uri:sub(1, #prefix) == prefix then return ngx.exit(404) end
    local session = cookie(session_name)
    if session then
        local _, status = request("check", route_id, session)
        if status == 200 then
            ngx.var.openflare_origin_cookie = table.concat(origin_cookies, "; ")
            return
        end
        if status ~= 401 then return ngx.exit(status == 403 and 403 or 503) end
    end
    -- Do not redirect uploads, API writes, or WebSocket upgrades to an HTML login.
    if ngx.req.get_method() ~= "GET" and ngx.req.get_method() ~= "HEAD" then return ngx.exit(401) end
    if ngx.var.http_upgrade then return ngx.exit(401) end
    local bytes = random.bytes(32, true)
    if not bytes then return ngx.exit(503) end
    local challenge = str.to_hex(bytes)
    ngx.header["Set-Cookie"] = set_cookie(challenge_name, challenge, 600)
    ngx.header["Cache-Control"] = "no-store"
    ngx.header["Referrer-Policy"] = "no-referrer"
    local return_url = "https://" .. ngx.var.host .. ngx.var.request_uri
    return ngx.redirect(control .. "/api/v1/site-auth/login?" .. ngx.encode_args({route_id = route_id, return_url = return_url, binding = digest(challenge)}), 302)
end

return M
