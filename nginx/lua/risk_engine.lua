local _M = {}

local ngx = ngx
local tonumber = tonumber
local math_min = math.min

local BLOCK_THRESHOLD = tonumber(os.getenv("RISK_BLOCK_THRESHOLD")) or 80
local LIMIT_THRESHOLD = tonumber(os.getenv("RISK_LIMIT_THRESHOLD")) or 50

local DECAY_FACTOR = 0.9
local MAX_RISK     = 100

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

function _M.run(ctx)
    local ip = ngx.var.realip_remote_addr or ngx.var.remote_addr

    ctx.security = ctx.security or {}
    local base_risk = ctx.security.risk or 0

    -- ================= SIGNAL CORRELATION =================
    local signals = ctx.security.signals or {}

    for _, s in ipairs(signals) do
        if s == "waf_sqli" then
            base_risk = base_risk + 20
        elseif s == "xff_spoof" then
            base_risk = base_risk + 15
        elseif s == "bad_bot" then
            base_risk = base_risk + 10
        elseif s == "rate_limit_hard" then
            base_risk = base_risk + 20
        elseif s == "redis_rate_exceeded" then
            base_risk = base_risk + 15
        end
    end

    -- ================= REDIS =================
    local red, err = get_redis()

    if not red then
        ngx.log(ngx.WARN, "[RISK] Redis unavailable: ", err)

        if base_risk >= BLOCK_THRESHOLD then
            return ngx.exit(403)
        elseif base_risk >= LIMIT_THRESHOLD then
            return ngx.exit(429)
        end

        ctx.security.risk_final = base_risk
        return
    end

    local key = "risk:v1:" .. ip

    local reputation = red:get(key)
    if not reputation or reputation == ngx.null then
        reputation = 0
    else
        reputation = tonumber(reputation) or 0
    end

    local final_risk = reputation * DECAY_FACTOR + base_risk

    -- momentum
    if base_risk > 30 then
        final_risk = final_risk + 10
    end

    -- forgiveness
    if base_risk < 10 then
        final_risk = final_risk * 0.8
    end

    final_risk = math_min(final_risk, MAX_RISK)

    red:set(key, final_risk, "EX", 3600)
    red:set_keepalive(10000, 100)

    ngx.log(ngx.INFO,
        "[RISK] ip=", ip,
        " base=", base_risk,
        " rep=", reputation,
        " final=", final_risk
    )

    if final_risk >= BLOCK_THRESHOLD then
        if metric_blocked then
            metric_blocked:inc(1, {"risk_block"})
        end
        return ngx.exit(403)
    end

    if final_risk >= LIMIT_THRESHOLD then
        if metric_blocked then
            metric_blocked:inc(1, {"risk_limit"})
        end
        return ngx.exit(429)
    end

    ctx.security.risk_final = final_risk
end

return _M