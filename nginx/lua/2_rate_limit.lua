local _M = {}

local limit_req = require "resty.limit.req"
local lim, err = limit_req.new("limit_req_store", 10, 20)

if not lim then
    ngx.log(ngx.ERR, "[RATE_LIMIT] Init failed: ", err)
end

function _M.run()
    if not lim then return nil end  -- fail-open

    local ip  = ngx.var.remote_addr
    local key = ngx.var.binary_remote_addr

    local delay, err = lim:incoming(key, true)

    if not delay then
        if err == "rejected" then
            ngx.log(ngx.WARN, "[RATE_LIMIT] Hard reject IP: ", ip)
            if metric_blocked then metric_blocked:inc(1, {"rate_limit"}) end
            return 429
        end
        ngx.log(ngx.ERR, "[RATE_LIMIT] Error: ", err)
        return 500
    end

    if delay > 0.5 then
        ngx.log(ngx.WARN, "[RATE_LIMIT] Burst reject IP: ", ip)
        if metric_blocked then metric_blocked:inc(1, {"rate_limit"}) end
        return 429
    end

    return nil  -- cho qua
end

return _M
