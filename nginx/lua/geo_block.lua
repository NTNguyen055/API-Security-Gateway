local _M = {}

-- ============================================================
-- GEO BLOCK — FINAL (CACHE-FIRST + FAIL-SAFE)
-- ============================================================

local ngx = ngx
local math_min = math.min

-- ============================================================
-- CONFIG
-- ============================================================

local ALLOWED_COUNTRIES = {
    ["VN"] = true,
    ["US"] = true,
    ["SG"] = true,
    ["JP"] = true,
}

local GEO_CACHE_TTL = 86400   -- 24h
local GEO_FAIL_TTL  = 60      -- giảm để retry nhanh hơn
local GEO_TIMEOUT   = 500     -- ms

-- ============================================================
-- FAST PRIVATE IP CHECK (NO REGEX)
-- ============================================================

local function is_private_ip(ip)
    if not ip then return false end

    return ip == "127.0.0.1"
        or ip:sub(1,4) == "10."
        or ip:sub(1,8) == "192.168."
        or ip:match("^172%.(1[6-9]|2[0-9]|3[01])%.")
end

-- ============================================================
-- LOOKUP (HTTP)
-- ============================================================

local function lookup_country(ip)
    local http = require "resty.http"
    local httpc = http.new()

    httpc:set_timeout(GEO_TIMEOUT)

    local res, err = httpc:request_uri(
        "http://ip-api.com/json/" .. ip .. "?fields=countryCode,status",
        {
            method = "GET",
            keepalive = true
        }
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

-- ============================================================
-- MAIN
-- ============================================================

function _M.run(ctx)
    local ip = ngx.var.remote_addr
    ctx.security = ctx.security or {}

    -- ========================================================
    -- PRIVATE IP (FAST PATH)
    -- ========================================================
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

    -- ========================================================
    -- CACHE HIT
    -- ========================================================
    local cached = cache:get(ip)

    if cached then
        if cached == "ALLOW" then
            ctx.security.geo_allowed = true
            return
        end

        -- cached country bị block
        ctx.security.geo_blocked = true
        ctx.security.geo_country = cached
        ctx.security.risk = math_min((ctx.security.risk or 0) + 35, 100)

        ngx.log(ngx.WARN,
            "[GEO][CACHE] Block country=", cached,
            " IP=", ip
        )

        if metric_blocked then
            metric_blocked:inc(1, {"geo_block"})
        end

        return
    end

    -- ========================================================
    -- LOOKUP (EXTERNAL)
    -- ========================================================
    local country, err = lookup_country(ip)

    if not country then
        -- fail-open + short cache
        cache:set(ip, "ALLOW", GEO_FAIL_TTL)

        ctx.security.geo_lookup_fail = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 10, 100)

        ngx.log(ngx.WARN,
            "[GEO] Lookup failed IP=", ip,
            " err=", err
        )

        return
    end

    -- ========================================================
    -- ALLOW
    -- ========================================================
    if country == "PRIVATE" or ALLOWED_COUNTRIES[country] then
        cache:set(ip, "ALLOW", GEO_CACHE_TTL)

        ctx.security.geo_allowed = true
        ctx.security.geo_country = country

        ngx.log(ngx.INFO,
            "[GEO] Allow country=", country,
            " IP=", ip
        )

        return
    end

    -- ========================================================
    -- BLOCK (SIGNAL ONLY)
    -- ========================================================
    cache:set(ip, country, GEO_CACHE_TTL)

    ctx.security.geo_blocked = true
    ctx.security.geo_country = country
    ctx.security.risk = math_min((ctx.security.risk or 0) + 35, 100)

    ngx.log(ngx.WARN,
        "[GEO] Block country=", country,
        " IP=", ip
    )

    if metric_blocked then
        metric_blocked:inc(1, {"geo_block"})
    end
end

return _M