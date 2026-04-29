local _M = {}

local ngx = ngx
local math_min = math.min

local ALLOWED_COUNTRIES = {
    ["VN"] = true,
    ["US"] = true,
    ["SG"] = true,
    ["JP"] = true,
}

local GEO_CACHE_TTL = 86400
local GEO_FAIL_TTL  = 60
local GEO_TIMEOUT   = 500

-- [FIX] Giới hạn số gọi API tối đa để tránh bị ban và treo hệ thống
local MAX_API_CALLS_PER_MIN = 40

local function is_private_ip(ip)
    if not ip then return false end

    return ip == "127.0.0.1"
        or ip == "::1"
        or ip:sub(1,4) == "10."
        or ip:sub(1,8) == "192.168."
        or ip:match("^172%.(1[6-9]|2[0-9]|3[01])%.")
end

local function lookup_country(ip)
    local http = require "resty.http"
    local httpc = http.new()

    httpc:set_timeout(GEO_TIMEOUT)

    local res, err = httpc:request_uri(
        "http://ip-api.com/json/" .. ip .. "?fields=countryCode,status",
        { method = "GET", keepalive = true }
    )

    if not res or res.status ~= 200 then
        return nil, err
    end

    local cjson = require "cjson.safe"
    local data = cjson.decode(res.body)

    if not data or data.status ~= "success" then
        return "PRIVATE"
    end

    return data.countryCode
end

function _M.run(ctx)
    local ip = ngx.var.realip_remote_addr or ngx.var.remote_addr
    ctx.security = ctx.security or {}
    ctx.security.signals = ctx.security.signals or {}

    if is_private_ip(ip) then
        ctx.security.geo_private = true
        return
    end

    local cache = ngx.shared.geo_cache

    if not cache then
        ctx.security.geo_cache_missing = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 5, 100)
        return
    end

    local cached = cache:get(ip)

    if cached then
        if cached == "A" then
            ctx.security.geo_allowed = true
            return
        end

        local country = cached:sub(3)

        ctx.security.geo_blocked = true
        ctx.security.geo_country = country

        local base = 25
        if ctx.security.bad_bot_scanner then base = base + 10 end
        if ctx.security.rate_limit_hard then base = base + 10 end

        ctx.security.risk = math_min((ctx.security.risk or 0) + base, 100)

        table.insert(ctx.security.signals, "geo_block")

        ngx.log(ngx.WARN,
            "[GEO][CACHE] Block country=", country,
            " IP=", ip
        )

        if metric_blocked then
            metric_blocked:inc(1, {"geo_block"})
        end

        return
    end

    -- Throttle lookup (chống Dogpile effect cho cùng 1 IP)
    local lock = cache:add("geo_lock:" .. ip, true, 5)
    if not lock then
        return
    end

    -- [FIX] Áp dụng Circuit Breaker: Kiểm tra xem phút này đã gọi API quá mức chưa
    local current_min = math.floor(ngx.time() / 60)
    local api_req_key = "api_req_count:" .. current_min
    local req_count, err = cache:incr(api_req_key, 1, 0, 60)

    if req_count and req_count > MAX_API_CALLS_PER_MIN then
        -- Cầu dao ngắt: Fail-open an toàn, không gọi API nữa
        cache:set(ip, "A", GEO_FAIL_TTL)
        ctx.security.geo_allowed = true
        
        if req_count == MAX_API_CALLS_PER_MIN + 1 then
            ngx.log(ngx.WARN, "[GEO] CIRCUIT BREAKER TRIPPED! API calls > ", MAX_API_CALLS_PER_MIN, "/min. Defaulting to ALLOW.")
        end
        return
    end

    local country, err = lookup_country(ip)

    if not country then
        cache:set(ip, "A", GEO_FAIL_TTL)

        ctx.security.geo_lookup_fail = true

        local base = 5
        if ctx.security.rate_limit_hard then base = base + 10 end

        ctx.security.risk = math_min((ctx.security.risk or 0) + base, 100)

        ngx.log(ngx.WARN,
            "[GEO] Lookup failed IP=", ip,
            " err=", err
        )

        return
    end

    if country == "PRIVATE" or ALLOWED_COUNTRIES[country] then
        cache:set(ip, "A", GEO_CACHE_TTL)

        ctx.security.geo_allowed = true
        ctx.security.geo_country = country

        return
    end

    cache:set(ip, "B:" .. country, GEO_CACHE_TTL)

    ctx.security.geo_blocked = true
    ctx.security.geo_country = country

    local base = 25
    if ctx.security.bad_bot_scanner then base = base + 10 end
    if ctx.security.rate_limit_hard then base = base + 10 end

    ctx.security.risk = math_min((ctx.security.risk or 0) + base, 100)

    table.insert(ctx.security.signals, "geo_block")

    ngx.log(ngx.WARN,
        "[GEO] Block country=", country,
        " IP=", ip
    )

    if metric_blocked then
        metric_blocked:inc(1, {"geo_block"})
    end
end

return _M