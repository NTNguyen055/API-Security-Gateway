local _M = {}

local limit_req = require "resty.limit.req"
local lim, err = limit_req.new("limit_req_store", 10, 20) 
-- 10 req/s, burst 20 (thực tế hơn)

if not lim then
    ngx.log(ngx.ERR, "[RATE_LIMIT] Init failed: ", err)
end

function _M.run()
    if not lim then return end

    local ip = ngx.var.remote_addr
    local key = ngx.var.binary_remote_addr

    local delay, err = lim:incoming(key, true)

    if not delay then
        if err == "rejected" then
            ngx.log(ngx.WARN, "[RATE_LIMIT] Hard reject IP: ", ip)
            return ngx.exit(429)
        end
        ngx.log(ngx.ERR, "[RATE_LIMIT] Error: ", err)
        return ngx.exit(500)
    end

    -- 🔥 SMART CONTROL
    if delay > 0.5 then
        ngx.log(ngx.WARN, "[RATE_LIMIT] Too aggressive IP: ", ip)
        return ngx.exit(429)
    end

    -- delay nhỏ → cho qua (không sleep)
end

return _M