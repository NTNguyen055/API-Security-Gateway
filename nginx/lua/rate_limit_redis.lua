local _M = {}

-- ============================================================
-- DISTRIBUTED RATE LIMIT — FINAL (REDIS + THROTTLE + SAFE)
-- ============================================================

local ngx = ngx
local tonumber = tonumber
local math_min = math.min

-- ============================================================
-- CONFIG
-- ============================================================

local REDIS_RATE_LIMIT = tonumber(os.getenv("REDIS_RATE_LIMIT")) or 30
local REDIS_RL_WINDOW  = tonumber(os.getenv("REDIS_RL_WINDOW"))  or 60

-- throttle Redis calls (giảm spam khi bị flood)
local LOCAL_THROTTLE_TTL = 1 -- seconds

-- ============================================================
-- REDIS SCRIPT (ATOMIC INCR + EXPIRE)
-- ============================================================

local REDIS_SCRIPT = [[
local key = KEYS[1]
local window = tonumber(ARGV[1])

local current = redis.call('INCR', key)
if current == 1 then
    redis.call('EXPIRE', key, window)
end

return current
]]

-- ============================================================
-- REDIS CONNECT
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

    -- ========================================================
    -- LOCAL THROTTLE (ANTI REDIS FLOOD)
    -- ========================================================
    local throttle = ngx.shared.rl_cache
    if throttle then
        local hit = throttle:get(ip)
        if hit then
            return
        end
        throttle:set(ip, true, LOCAL_THROTTLE_TTL)
    end

    -- ========================================================
    -- REDIS CONNECT
    -- ========================================================
    local red, err = get_redis()

    if not red then
        ngx.log(ngx.WARN, "[REDIS_RL] Redis down: ", err)

        ctx.security.redis_rl_fail = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 5, 100)

        return
    end

    -- ========================================================
    -- FIXED WINDOW COUNTER
    -- ========================================================
    local window_id = math.floor(ngx.time() / REDIS_RL_WINDOW)
    local key = "rrl:" .. ip .. ":" .. window_id

    local count, script_err = red:eval(
        REDIS_SCRIPT, 1, key, REDIS_RL_WINDOW
    )

    red:set_keepalive(10000, 100)

    if not count then
        ngx.log(ngx.ERR, "[REDIS_RL] Script error: ", script_err)

        ctx.security.redis_rl_error = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 10, 100)

        return
    end

    -- ========================================================
    -- SIGNAL LEVELS
    -- ========================================================

    local limit = REDIS_RATE_LIMIT

    -- 🟢 NORMAL
    if count <= limit * 0.7 then
        ctx.security.redis_rate_ok = true
        return
    end

    -- 🟡 WARNING
    if count <= limit then
        ctx.security.redis_rate_warn = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 10, 100)

        ngx.log(ngx.WARN,
            "[REDIS_RL] WARN IP=", ip,
            " count=", count, "/", limit
        )

        return
    end

    -- 🔴 EXCEEDED
    ctx.security.redis_rate_exceeded = true
    ctx.security.risk = math_min((ctx.security.risk or 0) + 10, 100)

    ngx.log(ngx.WARN,
        "[REDIS_RL] EXCEEDED IP=", ip,
        " count=", count, "/", limit
    )

    if metric_blocked then
        metric_blocked:inc(1, {"redis_rate_limit"})
    end

    -- không block tại đây → để risk_engine quyết định
end

return _M