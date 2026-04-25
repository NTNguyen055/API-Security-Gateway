local _M = {}

local redis = require "resty.redis"

-- ================= CONFIG =================
local REDIS_DOWN_TTL   = 5     -- circuit breaker
local NEG_CACHE_TTL    = 60    -- cache IP sạch
local POS_CACHE_TTL    = 600   -- cache IP bị block (lâu hơn để giảm load)
local REDIS_KEY_PREFIX = "bl:" -- key chuẩn: bl:<ip>

-- ================= REDIS =================
local function get_redis()
    local cb = ngx.shared.redis_down
    if cb and cb:get("down") then
        return nil, "circuit_open"
    end

    local red = redis:new()
    red:set_timeouts(100, 100, 100)

    local ok, err = red:connect("redis", 6379)
    if not ok then
        if cb then cb:set("down", true, REDIS_DOWN_TTL) end
        return nil, err
    end

    return red, nil
end

-- ================= CORE =================
function _M.run()
    -- ⚠️ Dùng IP đã được normalize từ XFF guard nếu có
    local ip = ngx.req.get_headers()["X-Real-IP"] or ngx.var.remote_addr

    local cache = ngx.shared.ip_blacklist
    if not cache then
        ngx.log(ngx.ERR, "[BLACKLIST] Missing shared dict")
        return nil
    end

    -- ================= L1 CACHE =================
    local cached = cache:get(ip)

    if cached ~= nil then
        -- true → blocked | false → safe
        if cached then
            -- không log spam
            return 403
        else
            return nil
        end
    end

    -- ================= REDIS =================
    local red, err = get_redis()
    if not red then
        ngx.log(ngx.WARN, "[BLACKLIST] Redis unavailable: ", err, " → fail-open")

        -- cache tạm tránh retry liên tục
        cache:set(ip, false, 5)
        return nil
    end

    -- ================= LOOKUP =================
    local key = REDIS_KEY_PREFIX .. ip
    local res, rerr = red:get(key)

    if rerr then
        ngx.log(ngx.ERR, "[BLACKLIST] Redis error: ", rerr)
        red:set_keepalive(10000, 100)

        cache:set(ip, false, 5)
        return nil
    end

    red:set_keepalive(10000, 100)

    -- ================= DECISION =================
    if res and res ~= ngx.null then
        -- 🔥 IP bị block
        cache:set(ip, true, POS_CACHE_TTL)

        ngx.log(ngx.WARN, "[BLACKLIST] Blocked IP: ", ip)

        if metric_blocked then
            metric_blocked:inc(1, {"ip_blacklist"})
        end

        return 403
    else
        -- ✅ IP sạch → negative cache
        cache:set(ip, false, NEG_CACHE_TTL)
        return nil
    end
end

return _M