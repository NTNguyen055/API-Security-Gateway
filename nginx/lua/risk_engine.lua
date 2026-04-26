local _M = {}

-- ================= THRESHOLDS =================

local BASE_BLOCK    = 50
local BASE_THROTTLE = 30
local BASE_LOG      = 15

local THRESHOLD_BAN = 70
local BAN_DURATION  = 1800

-- ================= REDIS KEYS =================

local BL_KEY_PREFIX    = "bl:v1:"
local BL_REASON_PREFIX = "bl_reason:v1:"
local BAN_GUARD_PREFIX = "ban_guard:v1:"

-- ================= TRUST =================

local TRUSTED_IPS = {
    ["127.0.0.1"] = true,
}

-- ================= ADAPTIVE THRESHOLD =================

local function adjust_threshold(score, flags)
    local multiplier = 1.0
    local f = table.concat(flags, "|")

    -- Attack signals → block nhanh hơn
    if f:find("scanner", 1, true)
    or f:find("sqli",    1, true)
    or f:find("xss",     1, true) then
        multiplier = 0.7
    end

    -- Geo block → thêm risk tuyệt đối
    if f:find("geo_block", 1, true) then
        score = score + 10
    end

    -- Hard rate limit → block nhanh hơn
    if f:find("rate_limit_hard",  1, true)
    or f:find("redis_rate_hard",  1, true) then
        multiplier = math.min(multiplier, 0.8)
    end

    -- ✅ THÊM: XFF spoof = nguy hiểm cao
    if f:find("xff_issue", 1, true) then
        multiplier = math.min(multiplier, 0.75)
    end

    return score, multiplier
end

-- ================= ASYNC BAN =================

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

        -- Anti-spam: chỉ ban 1 lần/60s
        local guard = red:get(BAN_GUARD_PREFIX .. t_ip)
        if guard and guard ~= ngx.null then
            red:set_keepalive(10000, 100)
            return
        end

        red:set(BAN_GUARD_PREFIX .. t_ip, 1,   "EX", 60)
        red:set(BL_KEY_PREFIX    .. t_ip, 1,   "EX", dur)
        red:set(BL_REASON_PREFIX .. t_ip, rsn, "EX", dur)

        red:set_keepalive(10000, 100)

        ngx.log(ngx.WARN,
            "[RISK][BAN] IP=", t_ip,
            " reason=", rsn,
            " duration=", dur, "s")
    end, ip, duration, reason)
end

-- ================= SCORE DECAY =================
-- Decay 50% từ lần request trước để giảm false-positive khi traffic hợp lệ burst
local function apply_decay(ip, score)
    local dict = ngx.shared.rl_counter
    if not dict then return score end

    local prev = dict:get("risk:" .. ip) or 0
    local new_score = (prev * 0.5) + score

    -- ✅ FIX: dùng TTL đủ lâu (120s) để decay có hiệu lực giữa các req
    dict:set("risk:" .. ip, new_score, 120)

    return new_score
end

-- ================= CORE =================

function _M.run()
    local ip    = ngx.ctx.real_ip or ngx.var.remote_addr
    local score = ngx.ctx.risk_score or 0
    local flags = ngx.ctx.flags or {}

    -- Fast path: score = 0 hoặc trusted
    if score == 0 then return nil end
    if TRUSTED_IPS[ip] then return nil end

    -- ================= COMPUTE =================
    score = apply_decay(ip, score)

    -- ✅ FIX: khai báo local multiplier đúng cách
    local multiplier
    score, multiplier = adjust_threshold(score, flags)

    local block_th    = BASE_BLOCK    * multiplier
    local throttle_th = BASE_THROTTLE * multiplier
    local log_th      = BASE_LOG      * multiplier

    local flag_str = table.concat(flags, "|")

    ngx.log(ngx.INFO,
        "[RISK] ip=", ip,
        " score=", string.format("%.1f", score),
        " flags=", flag_str,
        " th_block=", string.format("%.1f", block_th))

    -- ================= DECISION =================

    if score >= THRESHOLD_BAN then
        -- Hard ban → blacklist ngay + async persist
        local bl_cache = ngx.shared.ip_blacklist
        if bl_cache and not bl_cache:get(ip) then
            bl_cache:set(ip, true, BAN_DURATION)
            ban_ip_async(ip, BAN_DURATION, flag_str)
        end
        return 403

    elseif score >= block_th then
        return 403

    elseif score >= throttle_th then
        ngx.header["Retry-After"] = "60"
        return 429

    elseif score >= log_th then
        ngx.log(ngx.INFO,
            "[RISK][SUSPICIOUS] IP=", ip,
            " score=", string.format("%.1f", score),
            " flags=", flag_str)
    end

    return nil
end

return _M
