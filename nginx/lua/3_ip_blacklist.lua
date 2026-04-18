local _M = {}

local redis = require "resty.redis"

function _M.run()
    local red = redis:new()
    -- Timeout ngắn (200ms) để không treo worker khi Redis chậm
    red:set_timeouts(200, 200, 200)

    local ok, err = red:connect("redis", 6379)
    if not ok then
        ngx.log(ngx.ERR, "[BLACKLIST] Redis connect failed: ", err,
                " → fail-open")
        return  -- fail-open: cho qua nếu Redis không sẵn sàng
    end

    local ip = ngx.var.remote_addr
    local res, get_err = red:get("blacklist:" .. ip)

    if get_err then
        ngx.log(ngx.ERR, "[BLACKLIST] Redis GET error: ", get_err)
        red:close()
        return  -- fail-open
    end

    -- Trả connection về pool TRƯỚC khi exit để tránh connection leak
    red:set_keepalive(10000, 100)

    -- ngx.null = key không tồn tại trong Redis
    if res ~= ngx.null and res == "1" then
        ngx.log(ngx.WARN, "[BLACKLIST] Blocked IP: ", ip)
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
end

return _M
