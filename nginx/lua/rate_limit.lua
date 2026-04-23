local _M = {}

local lim

local function get_limiter()
    if not lim then
        local limit_req = require "resty.limit.req"

        local rate  = tonumber(os.getenv("RATE_LIMIT_RPS")) or 10
        local burst = tonumber(os.getenv("RATE_LIMIT_BURST")) or 20

        local l, err = limit_req.new("limit_req_store", rate, burst)
        if not l then
            ngx.log(ngx.ERR, "[RATE_LIMIT] Init failed: ", err)
            return nil
        end

        lim = l
    end
    return lim
end

function _M.run()
    local limiter = get_limiter()
    if not limiter then return nil end  -- fail-open

    local ip = ngx.var.remote_addr
    local ua = ngx.var.http_user_agent or "unknown"

    local key = ngx.var.binary_remote_addr .. ua

    local delay, err = limiter:incoming(key, true)

    if not delay then
        if err == "rejected" then
            ngx.log(ngx.WARN, "[RATE_LIMIT] Hard reject IP: ", ip)
            if metric_blocked then metric_blocked:inc(1, {"rate_limit_hard"}) end
            return 429
        end

        ngx.log(ngx.ERR, "[RATE_LIMIT] Error: ", err)
        return 500
    end

    -- Soft limit (delay nhẹ)
    if delay > 0 then
        if delay > 1 then
            ngx.log(ngx.WARN, "[RATE_LIMIT] Burst reject IP: ", ip)
            if metric_blocked then metric_blocked:inc(1, {"rate_limit_burst"}) end
            return 429
        end

        ngx.sleep(delay)
    end

    return nil
end

return _M