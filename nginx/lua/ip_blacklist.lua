local _M = {}

local ngx = ngx
local math_min = math.min

local CACHE_TTL_POSITIVE = 300
local CACHE_TTL_NEGATIVE = 5

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

function _M.run(ctx)
    local ip = ngx.var.realip_remote_addr or ngx.var.remote_addr
    ctx.security = ctx.security or {}
    ctx.security.signals = ctx.security.signals or {}

    local cache = ngx.shared.ip_blacklist

    -- ========================================================
    -- L1 CACHE
    -- ========================================================
    if cache then
        local val = cache:get(ip)

        if val ~= nil then
            if val == true then
                ctx.security.ip_blacklisted = true
                ctx.security.block = true
                ctx.security.risk = 100

                table.insert(ctx.security.signals, "ip_blacklist_cache")

                ngx.log(ngx.WARN, "[BLACKLIST][CACHE] IP=", ip)

                if metric_blocked then
                    metric_blocked:inc(1, {"ip_blacklist_cache"})
                end

                return
            end

            return
        end
    end

    -- ========================================================
    -- REDIS
    -- ========================================================
    local red, err = get_redis()

    if not red then
        ngx.log(ngx.WARN,
            "[BLACKLIST] Redis unavailable: ", err
        )

        ctx.security.redis_bl_fail = true

        if ctx.security.xff_spoof or ctx.security.bad_bot then
            ctx.security.risk = math_min((ctx.security.risk or 0) + 15, 100)
        else
            ctx.security.risk = math_min((ctx.security.risk or 0) + 5, 100)
        end

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

    if res == 1 or res == "1" then
        ngx.log(ngx.WARN, "[BLACKLIST] IP=", ip)

        if cache then
            cache:set(ip, true, CACHE_TTL_POSITIVE)
        end

        ctx.security.ip_blacklisted = true
        ctx.security.block = true
        ctx.security.risk = 100

        table.insert(ctx.security.signals, "ip_blacklist")

        if metric_blocked then
            metric_blocked:inc(1, {"ip_blacklist"})
        end

        return
    end

    -- NEGATIVE CACHE (smart)
    if cache and (ctx.security.risk or 0) < 20 then
        cache:set(ip, false, CACHE_TTL_NEGATIVE)
    end

    ctx.security.ip_clean = true
    table.insert(ctx.security.signals, "ip_clean")
end

return _M