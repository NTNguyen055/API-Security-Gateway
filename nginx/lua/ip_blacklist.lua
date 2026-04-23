local _M = {}

local redis = require "resty.redis"

function _M.run()
    local ip = ngx.var.remote_addr

    -- L1: shared memory cache
    local cache = ngx.shared.ip_blacklist
    if cache:get(ip) then
        ngx.log(ngx.WARN, "[BLACKLIST][CACHE] Blocked IP: ", ip)
        if metric_blocked then metric_blocked:inc(1, {"ip_blacklist_cache"}) end
        return 403
    end

    -- L2: Redis
    local red = redis:new()
    red:set_timeouts(200, 200, 200)

    local ok, err = red:connect("redis", 6379)
    if not ok then
        ngx.log(ngx.ERR, "[BLACKLIST] Redis connect failed: ", err, " → fail-open")
        return nil
    end

    local res, get_err = red:sismember("blacklist_ips", ip)

    if get_err then
        ngx.log(ngx.ERR, "[BLACKLIST] Redis error: ", get_err)
        red:set_keepalive(10000, 100, "redis_pool")
        return nil
    end

    red:set_keepalive(10000, 100)

    if res == 1 or res == "1" then
        ngx.log(ngx.WARN, "[BLACKLIST] Blocked IP: ", ip)

        -- cache lâu hơn để giảm Redis load
        cache:set(ip, true, 300)

        if metric_blocked then metric_blocked:inc(1, {"ip_blacklist"}) end

        return 403
    end

    return nil
end

return _M