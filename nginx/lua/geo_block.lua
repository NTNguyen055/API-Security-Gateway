local _M = {}

-- ================= CONFIG =================

local GEO_DB_PATH = "/etc/geoip/GeoLite2-Country.mmdb"

local ALLOWED_COUNTRIES = {
    ["VN"] = true,
    ["US"] = true,
    ["SG"] = true,
    ["JP"] = true,
}

local CACHE_TTL       = 86400
local CACHE_TTL_FAIL  = 300

local SCORE_GEO_BLOCK   = 50
local SCORE_GEO_UNKNOWN = 10

-- ================= INIT =================

local geoip
local geoip_ready = false

local function init_geoip()
    if geoip_ready then return true end

    local ok, lib = pcall(require, "resty.maxminddb")
    if not ok then
        ngx.log(ngx.ERR, "[GEO] Cannot load maxminddb: ", lib)
        return false
    end

    geoip = lib

    local ok2, err = geoip.init(GEO_DB_PATH)
    if not ok2 then
        ngx.log(ngx.ERR, "[GEO] Init DB failed: ", err)
        return false
    end

    geoip_ready = true
    ngx.log(ngx.NOTICE, "[GEO] GeoIP DB loaded")
    return true
end

-- ================= HELPERS =================

local function is_private_ip(ip)
    if not ip then return true end

    -- IPv4 private
    if ngx.re.find(ip,
        [[^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.)]], "jo") then
        return true
    end

    -- IPv6 private / loopback
    if ngx.re.find(ip, [[^(::1|fc00:|fd00:)]], "jo") then
        return true
    end

    return false
end

local function get_country(ip)
    if not geoip_ready then
        if not init_geoip() then
            return nil
        end
    end

    local res, err = geoip.lookup(ip, {"country", "iso_code"})

    if err then
        if err ~= "not found" then
            ngx.log(ngx.WARN, "[GEO] Lookup error IP=", ip, " err=", err)
        end
        return nil
    end

    return res
end

-- ================= MAIN =================

function _M.run()
    local ip = ngx.ctx.real_ip or ngx.var.remote_addr

    ngx.ctx.risk_score = ngx.ctx.risk_score or 0
    ngx.ctx.flags      = ngx.ctx.flags or {}

    -- ================= SKIP PRIVATE =================
    if is_private_ip(ip) then
        return nil
    end

    local cache = ngx.shared.geo_cache
    if not cache then
        ngx.log(ngx.ERR, "[GEO] Missing geo_cache")
        return nil
    end

    -- ================= CACHE =================
    local cached = cache:get(ip)

    if cached then
        if cached == "ALLOW" then
            return nil
        elseif cached == "UNKNOWN" then
            ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_GEO_UNKNOWN
            table.insert(ngx.ctx.flags, "geo_unknown")
            return nil
        else
            ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_GEO_BLOCK
            table.insert(ngx.ctx.flags, "geo_block")

            ngx.log(ngx.INFO,
                "[GEO][CACHE] Block IP=", ip,
                " country=", cached,
                " score=", ngx.ctx.risk_score)

            return nil
        end
    end

    -- ================= LOOKUP =================
    local country = get_country(ip)

    if not country then
        cache:set(ip, "UNKNOWN", CACHE_TTL_FAIL)

        ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_GEO_UNKNOWN
        table.insert(ngx.ctx.flags, "geo_unknown")

        ngx.log(ngx.INFO, "[GEO] Unknown country IP=", ip)
        return nil
    end

    -- ================= DECISION =================

    if ALLOWED_COUNTRIES[country] then
        cache:set(ip, "ALLOW", CACHE_TTL)

        ngx.log(ngx.INFO,
            "[GEO] Allowed IP=", ip,
            " country=", country)

        return nil
    end

    -- ❌ BLOCKED COUNTRY
    cache:set(ip, country, CACHE_TTL)

    ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_GEO_BLOCK
    table.insert(ngx.ctx.flags, "geo_block")

    ngx.log(ngx.WARN,
        "[GEO] Blocked IP=", ip,
        " country=", country,
        " score=", ngx.ctx.risk_score)

    return nil
end

return _M