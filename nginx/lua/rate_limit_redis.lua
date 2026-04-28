local _M = {}

local ngx = ngx
local tonumber = tonumber
local math_min = math.min

local REDIS_RATE_LIMIT = tonumber(os.getenv("REDIS_RATE_LIMIT")) or 30
local REDIS_RL_WINDOW  = tonumber(os.getenv("REDIS_RL_WINDOW"))  or 60

local LOCAL_THROTTLE_TTL = 1

local REDIS_SCRIPT = [[
local key = KEYS[1]
local window = tonumber(ARGV[1])

local current = redis.call('INCR', key)
if current == 1 then
    redis.call('EXPIRE', key, window)
end

return current
]]

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
    local uri = ngx.var.uri or ""
    ctx.security = ctx.security or {}
    ctx.security.signals = ctx.security.signals or {}

    -- LOCAL THROTTLE
    local throttle = ngx.shared.rl_cache
    if throttle and (ctx.security.risk or 0) < 30 then
        local hit = throttle:get(ip)
        if hit then
            return
        end
        throttle:set(ip, true, LOCAL_THROTTLE_TTL)
    end

    local red, err = get_redis()

    if not red then
        ngx.log(ngx.WARN, "[REDIS_RL] Redis down: ", err)

        ctx.security.redis_rl_fail = true

        if ctx.security.rate_limit_hard then
            ctx.security.risk = math_min((ctx.security.risk or 0) + 15, 100)
        else
            ctx.security.risk = math_min((ctx.security.risk or 0) + 5, 100)
        end

        return
    end

    local window_id = math.floor(ngx.time() / REDIS_RL_WINDOW)
    local key = "rrl:" .. ip .. ":" .. uri .. ":" .. window_id

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

    local limit = REDIS_RATE_LIMIT

    -- NORMAL
    if count <= limit * 0.7 then
        ctx.security.redis_rate_ok = true
        table.insert(ctx.security.signals, "redis_rate_ok")
        return
    end

    -- WARNING
    if count <= limit then
        ctx.security.redis_rate_warn = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 10, 100)

        table.insert(ctx.security.signals, "redis_rate_warn")

        ngx.log(ngx.WARN,
            "[REDIS_RL] WARN IP=", ip,
            " count=", count, "/", limit
        )

        return
    end

    -- EXCEEDED
    ctx.security.redis_rate_exceeded = true
    ctx.security.risk = math_min((ctx.security.risk or 0) + 20, 100)

    table.insert(ctx.security.signals, "redis_rate_exceeded")

    ngx.log(ngx.WARN,
        "[REDIS_RL] EXCEEDED IP=", ip,
        " count=", count, "/", limit
    )

    if metric_blocked then
        metric_blocked:inc(1, {"redis_rate_limit"})
    end
end

return _M