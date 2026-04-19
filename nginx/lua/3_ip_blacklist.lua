local _M = {}

local redis = require "resty.redis"

function _M.run()
    local ip = ngx.var.remote_addr

    -- =========================
    -- 1. CHECK CACHE (NGINX RAM)
    -- =========================
    local cache = ngx.shared.ip_blacklist
    if cache:get(ip) then
        ngx.log(ngx.WARN, "[BLACKLIST][CACHE] Blocked IP: ", ip)
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end

    -- =========================
    -- 2. CHECK REDIS
    -- =========================
    local red = redis:new()
    red:set_timeouts(200, 200, 200)

    local ok, err = red:connect("redis", 6379)
    if not ok then
        ngx.log(ngx.ERR, "[BLACKLIST] Redis connect failed: ", err,
                " IP: ", ip, " → fail-open")
        return
    end

    -- DÙNG SET thay vì key riêng
    local res, err = red:sismember("blacklist_ips", ip)

    if err then
        ngx.log(ngx.ERR, "[BLACKLIST] Redis error: ", err, " IP: ", ip)
        red:set_keepalive(10000, 100)
        return
    end

    -- trả connection về pool
    red:set_keepalive(10000, 100)

    -- =========================
    -- 3. Nếu bị blacklist
    -- =========================
    if res == 1 then
        ngx.log(ngx.WARN, "[BLACKLIST] Blocked IP: ", ip)

        -- cache lại trong Nginx (TTL 60s)
        cache:set(ip, true, 60)

        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
end

return _M