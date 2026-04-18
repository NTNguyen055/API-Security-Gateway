local _M = {}

-- Khởi tạo 1 lần ở module level, tái sử dụng cho mọi request
-- 20 req/s burst, 10 req/s sustained
local limit_req = require "resty.limit.req"
local lim, init_err = limit_req.new("limit_req_store", 20, 10)

if not lim then
    ngx.log(ngx.ERR, "[RATE_LIMIT] Init failed: ", init_err)
end

function _M.run()
    if not lim then
        return  -- fail-open nếu init thất bại
    end

    local key = ngx.var.binary_remote_addr
    local delay, err = lim:incoming(key, true)

    if not delay then
        if err == "rejected" then
            ngx.log(ngx.WARN, "[RATE_LIMIT] Rejected IP: ", ngx.var.remote_addr)
            return ngx.exit(429)
        end
        ngx.log(ngx.ERR, "[RATE_LIMIT] Unexpected error: ", err)
        return ngx.exit(500)
    end

    -- KHÔNG dùng ngx.sleep(delay) — blocking I/O sẽ treo Nginx worker
    -- Nếu delay > 0 tức đang ở burst zone → từ chối luôn
    if delay > 0 then
        ngx.log(ngx.WARN, "[RATE_LIMIT] Burst zone rejected IP: ", ngx.var.remote_addr)
        return ngx.exit(429)
    end
end

return _M
