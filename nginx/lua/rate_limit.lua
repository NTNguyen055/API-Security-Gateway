local _M = {}

local ngx      = ngx
local tonumber = tonumber
local math_min = math.min

-- ============================================================
-- CONFIG — đọc trong function để tránh nil khi module load sớm
-- ============================================================
local function get_config()
    return {
        rate      = tonumber(os.getenv("RATE_LIMIT_RPS"))    or 10,
        burst     = tonumber(os.getenv("RATE_LIMIT_BURST"))  or 20,
        bl_threshold = tonumber(os.getenv("AUTO_BL_THRESHOLD")) or 5,
        bl_window    = tonumber(os.getenv("AUTO_BL_WINDOW"))    or 60,
        bl_duration  = tonumber(os.getenv("AUTO_BL_DURATION"))  or 3600,
    }
end

-- ============================================================
-- LIMITER — lazy init per worker (shared dict giữ state)
-- ============================================================
local _limiter_cache = nil

local function get_limiter()
    if _limiter_cache then
        return _limiter_cache
    end

    local limit_req = require "resty.limit.req"
    local cfg = get_config()

    local l, err = limit_req.new("limit_req_store", cfg.rate, cfg.burst)
    if not l then
        ngx.log(ngx.ERR, "[RATE_LIMIT] Init failed: ", err)
        return nil
    end

    _limiter_cache = l
    return _limiter_cache
end

-- ============================================================
-- AUTO BLACKLIST — ghi đúng key để ip_blacklist.lua đọc được
-- ============================================================
local function auto_blacklist(ip, ctx)
    local cfg           = get_config()
    local counter_store = ngx.shared.rl_counter
    if not counter_store then return end

    local count = counter_store:incr("rl:" .. ip, 1, 0, cfg.bl_window)
    if not count then return end

    if count < cfg.bl_threshold or (ctx.security.risk or 0) < 50 then
        return
    end

    -- Lock để tránh race condition
    local lock = counter_store:add("bl_lock:" .. ip, 1, 5)
    if not lock then return end

    -- L1: shared dict cache — dùng số 1, không dùng boolean
    local bl_cache = ngx.shared.ip_blacklist
    if bl_cache then
        bl_cache:set(ip, 1, cfg.bl_duration)
    end

    -- L2: Redis async — ghi key "blacklist:<ip>" = "1" với TTL
    -- ip_blacklist.lua đã được cập nhật để đọc cả key này
    ngx.timer.at(0, function(premature, target_ip, duration)
        if premature then return end

        local redis = require "resty.redis"
        local red   = redis:new()
        red:set_timeouts(200, 200, 500)

        local ok, err = red:connect("redis", 6379)
        if not ok then
            ngx.log(ngx.ERR, "[AUTO_BL] Redis connect failed: ", err)
            return
        end

        -- Ghi key dạng string "1" với TTL — ip_blacklist.lua đọc key này
        local ok2, err2 = red:set("blacklist:" .. target_ip, "1", "EX", duration)
        if not ok2 then
            ngx.log(ngx.ERR, "[AUTO_BL] Redis set failed: ", err2)
        end

        red:set_keepalive(10000, 100)
        ngx.log(ngx.WARN, "[AUTO_BL] BLACKLISTED ip=", target_ip,
                           " duration=", duration, "s")
    end, ip, cfg.bl_duration)

    counter_store:delete("rl:" .. ip)
end

-- ============================================================
-- MAIN
-- ============================================================
function _M.run(ctx)
    local limiter = get_limiter()
    if not limiter then return end

    -- Ưu tiên dùng client_ip đã normalize từ xff_guard
    local ip  = (ctx.security and ctx.security.client_ip)
                or ngx.var.realip_remote_addr
                or ngx.var.remote_addr
    local uri = ngx.var.uri or ""
    local key = ip .. ":" .. uri

    ctx.security         = ctx.security or {}
    ctx.security.signals = ctx.security.signals or {}

    local delay, err = limiter:incoming(key, true)

    -- ── REJECTED (hard limit) ──────────────────────────────────
    if not delay then
        if err == "rejected" then
            ctx.security.rate_limit_hard = true
            ctx.security.block           = true   -- hard block ngay
            ctx.security.risk            = math_min((ctx.security.risk or 0) + 30, 100)

            table.insert(ctx.security.signals, "rate_limit_hard")
            ngx.log(ngx.WARN, "[RATE_LIMIT] HARD ip=", ip, " uri=", uri)

            auto_blacklist(ip, ctx)
            return
        end

        ngx.log(ngx.ERR, "[RATE_LIMIT] Error: ", err)
        return
    end

    -- ── BURST (trong ngưỡng nhưng cần throttle) ───────────────
    -- Không dùng ngx.sleep để tránh connection pile-up
    -- Thay vào đó tăng risk và để risk_engine quyết định
    if delay > 0 then
        ctx.security.rate_limit_burst = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 15, 100)

        table.insert(ctx.security.signals, "rate_limit_burst")

        ngx.log(ngx.WARN,
            "[RATE_LIMIT] BURST ip=", ip,
            " delay_ms=", string.format("%.0f", delay * 1000)
        )
        return
    end

    -- ── OK ────────────────────────────────────────────────────
    ctx.security.rate_ok = true
    table.insert(ctx.security.signals, "rate_ok")
end

return _M
