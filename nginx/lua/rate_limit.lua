local _M = {}

local lim

local function get_limiter()
    if lim then return lim end

    local limit_req = require "resty.limit.req"

    local rate  = tonumber(os.getenv("RATE_LIMIT_RPS"))   or 10
    local burst = tonumber(os.getenv("RATE_LIMIT_BURST")) or 20

    local l, err = limit_req.new("limit_req_store", rate, burst)
    if not l then
        ngx.log(ngx.ERR, "[RATE_LIMIT] Init failed: ", err)
        return nil
    end

    lim = l
    return lim
end

-- ✅ AUTO-BLACKLIST config (đọc từ .env, có fallback)
local AUTO_BL_THRESHOLD = tonumber(os.getenv("AUTO_BL_THRESHOLD")) or 5
local AUTO_BL_WINDOW    = tonumber(os.getenv("AUTO_BL_WINDOW"))    or 60   -- giây đếm
local AUTO_BL_DURATION  = tonumber(os.getenv("AUTO_BL_DURATION"))  or 3600 -- giây block

local function auto_blacklist(ip)
    local counter_store = ngx.shared.rl_counter
    if not counter_store then
        ngx.log(ngx.ERR, "[AUTO_BL] Missing shared dict 'rl_counter' in nginx.conf")
        return
    end

    -- Tăng counter, tự expire sau AUTO_BL_WINDOW giây
    local count, err = counter_store:incr("rl:" .. ip, 1, 0, AUTO_BL_WINDOW)
    if not count then
        ngx.log(ngx.ERR, "[AUTO_BL] Counter error: ", err)
        return
    end

    ngx.log(ngx.INFO, "[AUTO_BL] IP: ", ip, " reject_count=", count,
            "/", AUTO_BL_THRESHOLD)

    -- Chưa đủ ngưỡng → bỏ qua
    if count < AUTO_BL_THRESHOLD then
        return
    end

    -- ✅ Đủ ngưỡng → ghi vào L1 shared memory NGAY (non-blocking, ~0ms)
    local bl_cache = ngx.shared.ip_blacklist
    if bl_cache then
        bl_cache:set(ip, true, AUTO_BL_DURATION)
    end

    -- ✅ Ghi vào Redis qua ngx.timer (non-blocking, không treo worker)
    local ok, timer_err = ngx.timer.at(0, function(premature, target_ip, duration)
        if premature then return end

        local redis = require "resty.redis"
        local red = redis:new()
        red:set_timeouts(500, 500, 500)

        local conn_ok, conn_err = red:connect("redis", 6379)
        if not conn_ok then
            ngx.log(ngx.ERR, "[AUTO_BL] Redis connect failed: ", conn_err)
            return
        end

        -- Thêm vào Set blacklist_ips (dùng chung với ip_blacklist.lua)
        red:sadd("blacklist_ips", target_ip)
        -- Lưu thời điểm bị block để audit
        red:set("bl_time:" .. target_ip, ngx.time(), "EX", duration)

        red:set_keepalive(10000, 100)

        ngx.log(ngx.WARN, "[AUTO_BL] *** IP AUTO-BLACKLISTED: ", target_ip,
                " | duration=", duration, "s ***")

        if metric_blocked then
            metric_blocked:inc(1, {"auto_blacklist"})
        end
    end, ip, AUTO_BL_DURATION)

    if not ok then
        ngx.log(ngx.ERR, "[AUTO_BL] Timer failed: ", timer_err)
    end

    -- Reset counter để tránh trigger lại ngay
    counter_store:delete("rl:" .. ip)
end

function _M.run()
    local limiter = get_limiter()
    if not limiter then return nil end  -- fail-open

    local ip  = ngx.var.remote_addr
    local key = ngx.var.binary_remote_addr

    local delay, err = limiter:incoming(key, true)

    if not delay then
        if err == "rejected" then
            ngx.log(ngx.WARN, "[RATE_LIMIT] Hard reject IP: ", ip)
            if metric_blocked then metric_blocked:inc(1, {"rate_limit_hard"}) end
            auto_blacklist(ip)
            return 429
        end
        ngx.log(ngx.ERR, "[RATE_LIMIT] Error: ", err)
        return 500
    end

    -- KHÔNG dùng ngx.sleep() — blocking I/O treo Nginx Worker
    -- Mọi delay > 0 đều từ chối ngay: đề tài nhấn mạnh Non-blocking I/O
    if delay > 0 then
        ngx.log(ngx.WARN, "[RATE_LIMIT] Burst reject IP: ", ip,
                " delay=", string.format("%.3f", delay))
        if metric_blocked then metric_blocked:inc(1, {"rate_limit_burst"}) end
        auto_blacklist(ip)
        return 429
    end

    return nil
end

return _M
