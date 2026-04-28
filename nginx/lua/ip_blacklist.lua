local _M = {}

-- ============================================================
-- IP BLACKLIST — FINAL (L1 + L2 + NEGATIVE CACHE + FAIL-FAST)
-- ============================================================

local ngx = ngx
local math_min = math.min

-- ============================================================
-- CONFIG
-- ============================================================

local CACHE_TTL_POSITIVE = 300   -- IP blacklist (L1)
local CACHE_TTL_NEGATIVE = 5     -- IP sạch (giảm Redis load)

-- ============================================================
-- REDIS CONNECT
-- ============================================================
local function get_redis()
    local redis = require "resty.redis"
    local red = redis:new()

    red:set_timeouts(50, 50, 50)

    local ok, err = red:connect("redis", 6379)
    if not ok then
        return nil, err
    end

    return red
end

-- ============================================================
-- MAIN
-- ============================================================
function _M.run(ctx)
    local ip = ngx.var.remote_addr
    ctx.security = ctx.security or {}

    local cache = ngx.shared.ip_blacklist

    -- ========================================================
    -- L1 CACHE (POSITIVE + NEGATIVE)
    -- ========================================================
    if cache then
        local val = cache:get(ip)

        if val ~= nil then
            -- 🔴 BLACKLIST HIT
            if val == true then
                ctx.security.ip_blacklisted = true
                ctx.security.block = true
                ctx.security.risk = 100

                ngx.log(ngx.WARN, "[BLACKLIST][CACHE] IP=", ip)

                if metric_blocked then
                    metric_blocked:inc(1, {"ip_blacklist_cache"})
                end

                return -- 🔥 FAIL-FAST
            end

            -- 🟢 NEGATIVE CACHE (clean IP)
            return
        end
    end

    -- ========================================================
    -- L2 REDIS (SOURCE OF TRUTH)
    -- ========================================================
    local red, err = get_redis()

    if not red then
        ngx.log(ngx.WARN,
            "[BLACKLIST] Redis unavailable: ", err,
            " → fail-open"
        )

        ctx.security.redis_bl_fail = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 5, 100)

        return
    end

    local res, get_err = red:sismember("blacklist_ips", ip)

    red:set_keepalive(10000, 100)

    if get_err then
        ngx.log(ngx.ERR, "[BLACKLIST] Redis error: ", get_err)

        ctx.security.redis_bl_error = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 10, 100)

        return
    end

    -- ========================================================
    -- 🔴 BLACKLIST HIT
    -- ========================================================
    if res == 1 or res == "1" then
        ngx.log(ngx.WARN, "[BLACKLIST] IP=", ip)

        -- cache L1 (positive)
        if cache then
            cache:set(ip, true, CACHE_TTL_POSITIVE)
        end

        ctx.security.ip_blacklisted = true
        ctx.security.block = true
        ctx.security.risk = 100

        if metric_blocked then
            metric_blocked:inc(1, {"ip_blacklist"})
        end

        return -- 🔥 FAIL-FAST
    end

    -- ========================================================
    -- 🟢 NOT BLACKLISTED (NEGATIVE CACHE)
    -- ========================================================
    if cache then
        cache:set(ip, false, CACHE_TTL_NEGATIVE)
    end

    ctx.security.ip_clean = true
end

return _M