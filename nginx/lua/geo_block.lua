local _M = {}

--[[
    GEO-BLOCKING MODULE
    Dùng ip-api.com (free, không cần API key) để lookup quốc gia.
    Kết quả cache vào shared memory 24h để tránh gọi API lặp lại.

    Chiến lược: WHITELIST — chỉ cho phép các quốc gia trong danh sách.
    Phù hợp với ứng dụng nội địa (Việt Nam + các nước cho phép).
]]

-- ✅ Danh sách quốc gia được phép truy cập (ISO 3166-1 alpha-2)
local ALLOWED_COUNTRIES = {
    ["VN"] = true,  -- Việt Nam
    ["US"] = true,  -- Mỹ (AWS infrastructure)
    ["SG"] = true,  -- Singapore (AWS ap-southeast-1)
    ["JP"] = true,  -- Nhật (AWS ap-northeast-1 — region của RDS)
}

-- Cache 24 tiếng để giảm tải API
local GEO_CACHE_TTL = 86400

local function lookup_country(ip)
    local http = require "resty.http"
    local httpc = http.new()
    httpc:set_timeout(1000)  -- 1 giây timeout

    local res, err = httpc:request_uri(
        "http://ip-api.com/json/" .. ip .. "?fields=countryCode,status",
        { method = "GET" }
    )

    if not res or res.status ~= 200 then
        ngx.log(ngx.ERR, "[GEO] API error for IP: ", ip, " err=", err)
        return nil
    end

    local cjson = require "cjson.safe"
    local data, decode_err = cjson.decode(res.body)
    if not data or decode_err then
        ngx.log(ngx.ERR, "[GEO] JSON decode error: ", decode_err)
        return nil
    end

    if data.status ~= "success" then
        -- IP private/reserved → allow
        return "PRIVATE"
    end

    return data.countryCode
end

function _M.run()
    local ip = ngx.var.remote_addr

    -- Bỏ qua IP private (localhost, Docker network, AWS internal)
    if ip == "127.0.0.1" or
       ngx.re.find(ip, [[^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)]], "jo") then
        return nil
    end

    local cache = ngx.shared.geo_cache
    if not cache then
        ngx.log(ngx.ERR, "[GEO] Missing shared dict 'geo_cache' in nginx.conf")
        return nil  -- fail-open
    end

    -- L1: Kiểm tra cache trước
    local cached = cache:get(ip)
    if cached then
        if cached == "ALLOW" or cached == "PRIVATE" then
            return nil
        end
        ngx.log(ngx.WARN, "[GEO][CACHE] Blocked country=", cached, " IP=", ip)
        if metric_blocked then metric_blocked:inc(1, {"geo_block"}) end
        return 403
    end

    -- L2: Gọi API lookup (non-blocking vì dùng lua-resty-http)
    local country = lookup_country(ip)

    if not country then
        -- API lỗi → fail-open, cache ngắn để retry sau
        cache:set(ip, "ALLOW", 300)
        return nil
    end

    -- Lưu cache
    if country == "PRIVATE" or ALLOWED_COUNTRIES[country] then
        cache:set(ip, "ALLOW", GEO_CACHE_TTL)
        ngx.log(ngx.INFO, "[GEO] Allowed country=", country, " IP=", ip)
        return nil
    else
        cache:set(ip, country, GEO_CACHE_TTL)
        ngx.log(ngx.WARN, "[GEO] Blocked country=", country, " IP=", ip)
        if metric_blocked then metric_blocked:inc(1, {"geo_block"}) end
        return 403
    end
end

return _M
