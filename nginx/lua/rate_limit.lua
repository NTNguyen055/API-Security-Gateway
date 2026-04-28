local _M = {}

-- ============================================================
-- RATE LIMIT — FINAL (HIGH PERFORMANCE + SAFE)
-- ============================================================

local ngx = ngx
local tonumber = tonumber
local math_min = math.min

local lim

-- ============================================================
-- INIT LIMITER (SINGLETON)
-- ============================================================
local function get_limiter()
    if lim then
        return lim
    end

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

-- ============================================================
-- AUTO BLACKLIST CONFIG
-- ============================================================
local AUTO_BL_THRESHOLD = tonumber(os.getenv("AUTO_BL_THRESHOLD")) or 5
local AUTO_BL_WINDOW    = tonumber(os.getenv("AUTO_BL_WINDOW"))    or 60
local AUTO_BL_DURATION  = tonumber(os.getenv("AUTO_BL_DURATION"))  or 3600

-- ============================================================
-- AUTO BLACKLIST (SAFE + THROTTLED)
-- ============================================================
local function auto_blacklist(ip)
    local counter_store = ngx.shared.rl_counter
    if not counter_store then return end

    -- đếm số lần vi phạm
    local count = counter_store:incr("rl:" .. ip, 1, 0, AUTO_BL_WINDOW)
    if not count then return end

    if count < AUTO_BL_THRESHOLD then
        return
    end

    -- tránh spawn nhiều timer
    local lock = counter_store:add("bl_lock:" .. ip, true, 5)
    if not lock then
        return
    end

    -- L1 cache ngay lập tức
    local bl_cache = ngx.shared.ip_blacklist
    if bl_cache then
        bl_cache:set(ip, true, AUTO_BL_DURATION)
    end

    -- async Redis (non-blocking)
    ngx.timer.at(0, function(premature, target_ip, duration)
        if premature then return end

        local redis = require "resty.redis"
        local red = redis:new()
        red:set_timeouts(100, 100, 100)

        if not red:connect("redis", 6379) then
            return
        end

        local ok = red:sadd("blacklist_ips", target_ip)
        if not ok then
            ngx.log(ngx.ERR, "[AUTO_BL] Redis SADD failed")
        end

        red:set("bl_time:" .. target_ip, ngx.time(), "EX", duration)
        red:set_keepalive(10000, 100)

        ngx.log(ngx.WARN, "[AUTO_BL] BLACKLISTED: ", target_ip)
    end, ip, AUTO_BL_DURATION)

    -- reset counter
    counter_store:delete("rl:" .. ip)
end

-- ============================================================
-- MAIN
-- ============================================================
function _M.run(ctx)
    local limiter = get_limiter()
    if not limiter then
        return -- fail-open
    end

    local ip  = ngx.var.remote_addr
    local key = ngx.var.binary_remote_addr

    ctx.security = ctx.security or {}

    local delay, err = limiter:incoming(key, true)

    -- ========================================================
    -- HARD REJECT (ABUSE)
    -- ========================================================
    if not delay then
        if err == "rejected" then
            ctx.security.rate_limit_hard = true

            local r = (ctx.security.risk or 0) + 30
            ctx.security.risk = math_min(r, 100)

            ngx.log(ngx.WARN, "[RATE_LIMIT] HARD IP=", ip)

            -- chỉ blacklist khi HARD
            auto_blacklist(ip)
            return
        end

        ngx.log(ngx.ERR, "[RATE_LIMIT] Error: ", err)
        return
    end

    -- ========================================================
    -- BURST (SOFT ABUSE)
    -- ========================================================
    if delay > 0 then
        ctx.security.rate_limit_burst = true

        local r = (ctx.security.risk or 0) + 15
        ctx.security.risk = math_min(r, 100)

        -- KHÔNG blacklist ở mức này (tránh false positive)

        ngx.log(ngx.WARN,
            "[RATE_LIMIT] BURST IP=", ip,
            " delay=", string.format("%.3f", delay)
        )

        return
    end

    -- ========================================================
    -- NORMAL
    -- ========================================================
    ctx.security.rate_ok = true
end

return _M