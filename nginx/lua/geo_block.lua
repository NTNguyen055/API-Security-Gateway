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
local SCORE_GEO_BLOCK = 50

-- ================= INIT (ONCE PER WORKER) =================

local geoip = nil
local geoip_ready = false

local function init_geoip()
    if geoip_ready then return true end

    local ok, lib = pcall(require, "resty.maxminddb")
    if not ok then
        ngx.log(ngx.ERR, "[GEO] Failed to load resty.maxminddb: ", lib)
        return false
    end

    geoip = lib

    local ok2, err = geoip.init(GEO_DB_PATH)
    if not ok2 then
        ngx.log(ngx.ERR, "[GEO] Failed to init DB: ", err)
        return false
    end

    geoip_ready = true
    ngx.log(ngx.NOTICE, "[GEO] GeoIP DB loaded successfully")

    return true
end

-- ================= CORE =================

local function get_country(ip)
    if not geoip_ready then
        if not init_geoip() then
            return nil
        end
    end

    local res, err = geoip.lookup(ip)

    if not res then
        ngx.log(ngx.ERR, "[GEO] Lookup failed: ", err)
        return nil
    end

    return res and res.country and res.country.iso_code
end

-- ================= MAIN =================

function _M.run()
    local ip = ngx.ctx.real_ip or ngx.var.remote_addr

    -- scoring context
    ngx.ctx.risk_score = ngx.ctx.risk_score or 0
    ngx.ctx.flags      = ngx.ctx.flags or {}

    -- ================= SKIP PRIVATE =================
    if ngx.re.find(ip,
        [[^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.)]], "jo") then
        return nil
    end

    local cache = ngx.shared.geo_cache
    if not cache then
        ngx.log(ngx.ERR, "[GEO] Missing shared dict geo_cache")
        return nil
    end

    -- ================= L1 CACHE =================
    local cached = cache:get(ip)

    if cached then
        if cached == "ALLOW" then
            return nil
        else
            -- blocked country cached
            ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_GEO_BLOCK
            table.insert(ngx.ctx.flags, "geo_block")

            ngx.log(ngx.WARN,
                "[GEO][CACHE] Block IP=", ip,
                " country=", cached,
                " score=", ngx.ctx.risk_score)

            return nil
        end
    end

    -- ================= LOOKUP =================
    local country = get_country(ip)

    if not country then
        -- fail-open
        cache:set(ip, "ALLOW", CACHE_TTL_FAIL)

        ngx.log(ngx.WARN,
            "[GEO] Fail-open IP=", ip)

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

    -- ❌ NOT ALLOWED
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