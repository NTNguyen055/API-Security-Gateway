local _M = {}

--[[
    RISK ENGINE — Pipeline Aggregator
    -----------------------------------
    Module CUỐI trong pipeline.
    Đọc ngx.ctx.risk_score được tích lũy từ tất cả module trước,
    ra quyết định block/allow/throttle dựa trên ngưỡng.

    Thứ tự pipeline:
    ip_blacklist → xff_guard → geo_block → bad_bot
    → rate_limit → rate_limit_redis → waf → jwt_auth
    → risk_engine  ← ĐÂY
]]

-- ================= THRESHOLDS =================
local THRESHOLD_BLOCK    = 50   -- block ngay
local THRESHOLD_THROTTLE = 30   -- trả 429 (too many requests)
local THRESHOLD_LOG      = 15   -- chỉ log, cho qua

-- Auto-ban threshold: score cao → ban Redis luôn
local THRESHOLD_BAN      = 70
local BAN_DURATION       = 1800  -- 30 phút

-- ================= KEY PREFIX CHUẨN =================
-- Phải khớp với ip_blacklist.lua: "bl:v1:<ip>"
local BL_KEY_PREFIX    = "bl:v1:"
local BL_REASON_PREFIX = "bl_reason:v1:"

-- ================= BAN ASYNC =================
local function ban_ip_async(ip, duration, reason)
    ngx.timer.at(0, function(premature, t_ip, dur, rsn)
        if premature then return end

        local redis = require "resty.redis"
        local red = redis:new()
        red:set_timeouts(500, 500, 500)

        local ok, err = red:connect("redis", 6379)
        if not ok then
            ngx.log(ngx.ERR, "[RISK] Redis connect failed: ", err)
            return
        end

        -- FIX: dùng key prefix chuẩn bl:v1: để khớp với ip_blacklist.lua
        red:set(BL_KEY_PREFIX .. t_ip,    1,   "EX", dur)
        red:set(BL_REASON_PREFIX .. t_ip, rsn, "EX", dur)
        red:set_keepalive(10000, 100)

        ngx.log(ngx.WARN, "[RISK] Auto-banned IP=", t_ip,
                " reason=", rsn, " duration=", dur, "s")
    end, ip, duration, reason)
end

-- ================= CORE =================
function _M.run()
    local score  = ngx.ctx.risk_score or 0
    local flags  = ngx.ctx.flags or {}
    local ip     = ngx.ctx.real_ip or ngx.var.remote_addr

    if score == 0 then
        return nil
    end

    local flag_str = table.concat(flags, "|")

    ngx.log(ngx.INFO,
        "[RISK] IP=", ip,
        " score=", score,
        " flags=", flag_str
    )

    -- ── DECISION ──

    if score >= THRESHOLD_BAN then
        local bl_cache = ngx.shared.ip_blacklist
        if bl_cache and not bl_cache:get(ip) then
            bl_cache:set(ip, true, BAN_DURATION)
            ban_ip_async(ip, BAN_DURATION, flag_str)
        end

        ngx.log(ngx.WARN,
            "[RISK] AUTO-BAN IP=", ip,
            " score=", score,
            " flags=", flag_str
        )

        if metric_blocked then metric_blocked:inc(1, {"risk_ban"}) end
        return 403

    elseif score >= THRESHOLD_BLOCK then
        ngx.log(ngx.WARN,
            "[RISK] BLOCK IP=", ip,
            " score=", score,
            " flags=", flag_str
        )

        if metric_blocked then metric_blocked:inc(1, {"risk_block"}) end
        return 403

    elseif score >= THRESHOLD_THROTTLE then
        ngx.log(ngx.WARN,
            "[RISK] THROTTLE IP=", ip,
            " score=", score,
            " flags=", flag_str
        )

        ngx.header["Retry-After"] = "60"
        if metric_blocked then metric_blocked:inc(1, {"risk_throttle"}) end
        return 429

    elseif score >= THRESHOLD_LOG then
        ngx.log(ngx.INFO,
            "[RISK] SUSPICIOUS IP=", ip,
            " score=", score,
            " flags=", flag_str
        )
    end

    return nil
end

return _M
