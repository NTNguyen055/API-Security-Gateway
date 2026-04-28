local _M = {}

-- ============================================================
-- ADAPTIVE RISK ENGINE — FINAL (OPTIMIZED)
-- ============================================================

local ngx = ngx
local tonumber = tonumber
local math_min = math.min

-- ============================================================
-- CONFIG
-- ============================================================

local BLOCK_THRESHOLD = tonumber(os.getenv("RISK_BLOCK_THRESHOLD")) or 80
local LIMIT_THRESHOLD = tonumber(os.getenv("RISK_LIMIT_THRESHOLD")) or 50

local DECAY_FACTOR = 0.9
local MAX_RISK     = 100

-- ============================================================
-- REDIS
-- ============================================================

local function get_redis()
    local redis = require "resty.redis"
    local red = redis:new()

    red:set_timeouts(50, 50, 50)

    local ok, err = red:connect("redis", 6379)
    if not ok then
        return nil, err
    end

    return red
end

-- ============================================================
-- MAIN
-- ============================================================

function _M.run(ctx)
    local ip = ngx.var.remote_addr

    ctx.security = ctx.security or {}
    local base_risk = ctx.security.risk or 0

    -- ========================================================
    -- HARD BLOCK (FAIL-FAST)
    -- ========================================================
    if ctx.security.block then
        ngx.log(ngx.WARN, "[RISK] HARD BLOCK IP=", ip)
        return ngx.exit(403)
    end

    -- ========================================================
    -- REDIS CONNECT
    -- ========================================================
    local red, err = get_redis()

    if not red then
        ngx.log(ngx.WARN, "[RISK] Redis unavailable: ", err)

        -- fallback: dùng base risk
        if base_risk >= BLOCK_THRESHOLD then
            return ngx.exit(403)
        elseif base_risk >= LIMIT_THRESHOLD then
            return ngx.exit(429)
        end

        ctx.security.risk_final = base_risk
        return
    end

    -- ========================================================
    -- LOAD REPUTATION (1 GET ONLY)
    -- ========================================================
    local key = "risk:" .. ip

    local reputation, get_err = red:get(key)
    if not reputation or reputation == ngx.null then
        reputation = 0
    else
        reputation = tonumber(reputation) or 0
    end

    if get_err then
        ngx.log(ngx.ERR, "[RISK] Redis GET failed: ", get_err)
    end

    -- ========================================================
    -- COMPUTE FINAL SCORE (NO DOUBLE COUNT)
    -- ========================================================
    local final_risk = reputation * DECAY_FACTOR + base_risk

    -- cap để tránh overflow
    final_risk = math_min(final_risk, MAX_RISK)

    -- ========================================================
    -- SAVE REPUTATION (1 SET)
    -- ========================================================
    local ok, set_err = red:set(key, final_risk, "EX", 3600)
    if not ok then
        ngx.log(ngx.ERR, "[RISK] Redis SET failed: ", set_err)
    end

    red:set_keepalive(10000, 100)

    -- ========================================================
    -- LOG
    -- ========================================================
    ngx.log(ngx.INFO,
        "[RISK] ip=", ip,
        " base=", base_risk,
        " rep=", reputation,
        " final=", final_risk
    )

    -- ========================================================
    -- DECISION ENGINE
    -- ========================================================

    -- 🔴 BLOCK
    if final_risk >= BLOCK_THRESHOLD then
        ngx.log(ngx.WARN, "[RISK] BLOCK IP=", ip)

        if metric_blocked then
            metric_blocked:inc(1, {"risk_block"})
        end

        return ngx.exit(403)
    end

    -- 🟠 RATE LIMIT
    if final_risk >= LIMIT_THRESHOLD then
        ngx.log(ngx.WARN, "[RISK] LIMIT IP=", ip)

        if metric_blocked then
            metric_blocked:inc(1, {"risk_limit"})
        end

        return ngx.exit(429)
    end

    -- 🟢 ALLOW
    ctx.security.risk_final = final_risk
end

return _M