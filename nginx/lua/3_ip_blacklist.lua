local _M = {}

local redis = require "resty.redis"

function _M.run()
    local ip = ngx.var.remote_addr

    -- L1: check Nginx shared memory cache trước (nhanh nhất)
    local cache = ngx.shared.ip_blacklist
    if cache:get(ip) then
        ngx.log(ngx.WARN, "[BLACKLIST][CACHE] Blocked IP: ", ip)
        return 403
    end

    -- L2: check Redis
    local red = redis:new()
    red:set_timeouts(200, 200, 200)

    local ok, err = red:connect("redis", 6379)
    if not ok then
        ngx.log(ngx.ERR, "[BLACKLIST] Redis connect failed: ", err, " → fail-open")
        return nil  -- fail-open
    end

    local res, get_err = red:sismember("blacklist_ips", ip)

    if get_err then
        ngx.log(ngx.ERR, "[BLACKLIST] Redis error: ", get_err)
        red:set_keepalive(10000, 100)
        return nil  -- fail-open
    end

    red:set_keepalive(10000, 100)

    if res == 1 then
        ngx.log(ngx.WARN, "[BLACKLIST] Blocked IP: ", ip)
        cache:set(ip, true, 60)  -- cache 60s
        return 403
    end

    return nil  -- cho qua
end

return _M
