local _M = {}

local ngx      = ngx
local tonumber = tonumber
local math_min = math.min

-- Đọc trong function vì nginx.conf cần khai báo env trước
local function get_config()
    return {
        block_threshold = tonumber(os.getenv("RISK_BLOCK_THRESHOLD")) or 80,
        limit_threshold = tonumber(os.getenv("RISK_LIMIT_THRESHOLD")) or 50,
    }
end

local DECAY_FACTOR = 0.9
local MAX_RISK     = 100

-- ============================================================
-- REDIS HELPER — timeout tăng lên 200/500ms, db 0
-- ============================================================
local function get_redis()
    local redis = require "resty.redis"
    local red   = redis:new()

    red:set_timeouts(200, 200, 500)

    local ok, err = red:connect("redis", 6379)
    if not ok then
        return nil, err
    end

    return red
end

-- ============================================================
-- SIGNAL CORRELATION
-- Chỉ cộng thêm điểm cho signal KHÔNG được tính trong module gốc
-- Tránh double-counting (module gốc đã cộng vào ctx.security.risk)
-- ============================================================
local SIGNAL_BONUS = {
    -- xff_private_client: module gốc cộng +20, bonus correlation thêm +5
    xff_private_client  = 5,
    -- bad_bot_scanner: module gốc cộng +50, bonus thêm +10 khi kết hợp
    bad_bot_scanner     = 10,
    -- geo_block kết hợp với signal khác mới cộng thêm
    geo_block           = 5,
    -- empty_ua kết hợp: suspicious hơn
    empty_ua            = 5,
}

-- ============================================================
-- MAIN — KHÔNG gọi ngx.exit() trực tiếp
-- Trả về action qua ctx để nginx.conf xử lý (tránh bị pcall catch)
-- ============================================================
function _M.run(ctx)
    local cfg = get_config()

    -- Ưu tiên dùng client_ip đã normalize từ xff_guard
    local ip = (ctx.security and ctx.security.client_ip)
               or ngx.var.realip_remote_addr
               or ngx.var.remote_addr

    ctx.security         = ctx.security or {}
    local base_risk      = ctx.security.risk or 0
    local signals        = ctx.security.signals or {}

    -- ── SIGNAL CORRELATION (chỉ bonus, không double-count) ────
    local bonus = 0
    local signal_set = {}
    for _, s in ipairs(signals) do
        signal_set[s] = true
    end

    for signal, points in pairs(SIGNAL_BONUS) do
        if signal_set[signal] then
            bonus = bonus + points
        end
    end

    -- Thêm bonus khi có sự kết hợp nguy hiểm
    if signal_set["waf_sqli"] and signal_set["bad_bot_scanner"] then
        bonus = bonus + 15  -- SQLi từ scanner — rất nguy hiểm
    end
    if signal_set["rate_limit_hard"] and signal_set["geo_block"] then
        bonus = bonus + 10  -- DDoS từ nước bị chặn
    end
    if signal_set["jwt_invalid"] and signal_set["rate_limit_hard"] then
        bonus = bonus + 10  -- Brute force JWT
    end

    base_risk = math_min(base_risk + bonus, MAX_RISK)

    -- ── REDIS REPUTATION ──────────────────────────────────────
    local red, err = get_redis()

    if not red then
        ngx.log(ngx.WARN, "[RISK] Redis unavailable: ", err)

        -- Fallback: quyết định dựa trên base_risk
        if base_risk >= cfg.block_threshold then
            ctx.security.risk_action = "block"
        elseif base_risk >= cfg.limit_threshold then
            ctx.security.risk_action = "limit"
        end

        ctx.security.risk_final = base_risk
        return
    end

    local key        = "risk:v1:" .. ip
    local reputation = red:get(key)

    if not reputation or reputation == ngx.null then
        reputation = 0
    else
        reputation = tonumber(reputation) or 0
    end

    -- Công thức: reputation cũ decay + base_risk hiện tại
    local final_risk = reputation * DECAY_FACTOR + base_risk

    -- Momentum: request xấu liên tiếp tăng nhanh hơn
    if base_risk > 30 then
        final_risk = final_risk + 10
    end

    -- Forgiveness: request sạch giảm dần reputation
    if base_risk < 10 then
        final_risk = final_risk * 0.8
    end

    final_risk = math_min(final_risk, MAX_RISK)

    -- Ghi reputation mới vào Redis (TTL 1 giờ)
    red:set(key, string.format("%.2f", final_risk), "EX", 3600)
    red:set_keepalive(10000, 100)

    -- Log đầy đủ context để forensics
    ngx.log(ngx.INFO,
        "[RISK] ip=", ip,
        " base=", string.format("%.1f", base_risk),
        " rep=", string.format("%.1f", reputation),
        " bonus=", bonus,
        " final=", string.format("%.1f", final_risk),
        " signals=[", table.concat(signals, ","), "]"
    )

    -- ── QUYẾT ĐỊNH — set action vào ctx, KHÔNG gọi ngx.exit() ─
    -- nginx.conf sẽ đọc ctx.security.risk_action và gọi ngx.exit()
    if final_risk >= cfg.block_threshold then
        ngx.log(ngx.WARN,
            "[RISK] BLOCK ip=", ip,
            " final=", string.format("%.1f", final_risk),
            " signals=[", table.concat(signals, ","), "]"
        )

        if metric_blocked then
            metric_blocked:inc(1, {"risk_block"})
        end

        ctx.security.risk_action = "block"

    elseif final_risk >= cfg.limit_threshold then
        ngx.log(ngx.WARN,
            "[RISK] LIMIT ip=", ip,
            " final=", string.format("%.1f", final_risk)
        )

        if metric_blocked then
            metric_blocked:inc(1, {"risk_limit"})
        end

        ctx.security.risk_action = "limit"
    end

    ctx.security.risk_final = final_risk
end

return _M
