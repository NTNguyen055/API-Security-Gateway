local _M = {}

-- ================= CONFIG =================

local REDIS_RATE_LIMIT = tonumber(os.getenv("REDIS_RATE_LIMIT")) or 30
local REDIS_RL_WINDOW  = tonumber(os.getenv("REDIS_RL_WINDOW"))  or 60

-- Risk scoring
local SCORE_REDIS_SOFT = 10
local SCORE_REDIS_HARD = 25

-- Redis circuit breaker (shared dict)
local REDIS_DOWN_TTL = 5

-- ================= REDIS SCRIPT =================

local REDIS_SCRIPT = [[
local key = KEYS[1]
local limit = tonumber(ARGV[1])
local window = tonumber(ARGV[2])

local current = redis.call('INCR', key)
if current == 1 then
    redis.call('EXPIRE', key, window)
end

return current
]]

-- ================= REDIS CONNECT =================

local function get_redis()
    -- 🔥 circuit breaker
    local cb = ngx.shared.redis_down
    if cb and cb:get("down") then
        return nil, "circuit_open"
    end

    local redis = require "resty.redis"
    local red = redis:new()
    red:set_timeouts(100, 100, 100)

    local ok, err = red:connect("redis", 6379)
    if not ok then
        if cb then cb:set("down", true, REDIS_DOWN_TTL) end
        return nil, err
    end

    return red, nil
end

-- ================= CORE =================

function _M.run()
    -- 🔥 unified IP
    local ip = ngx.ctx.real_ip or ngx.var.remote_addr

    -- init scoring context
    ngx.ctx.risk_score = ngx.ctx.risk_score or 0
    ngx.ctx.flags      = ngx.ctx.flags or {}

    -- ❗ Nếu local rate_limit đã flag nặng → skip Redis (tránh double punish)
    if ngx.ctx.flags and table.concat(ngx.ctx.flags, ","):find("rate_limit_hard") then
        return nil
    end

    local red, err = get_redis()
    if not red then
        ngx.log(ngx.WARN, "[REDIS_RL] Redis unavailable: ", err, " → skip")
        return nil
    end

    -- 🔥 Key nâng cao (IP + UA)
    local ua = ngx.var.http_user_agent or ""
    local window_id = math.floor(ngx.time() / REDIS_RL_WINDOW)
    local key = "rrl:" .. ip .. ":" .. ua .. ":" .. window_id

    local count, script_err = red:eval(
        REDIS_SCRIPT, 1,
        key,
        REDIS_RATE_LIMIT,
        REDIS_RL_WINDOW
    )

    red:set_keepalive(10000, 100)

    if not count then
        ngx.log(ngx.ERR, "[REDIS_RL] Script error: ", script_err)
        return nil
    end

    ngx.log(ngx.INFO, "[REDIS_RL] IP=", ip,
            " count=", count, "/", REDIS_RATE_LIMIT)

    -- ================= SCORING =================

    if count > REDIS_RATE_LIMIT then
        ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_REDIS_HARD
        table.insert(ngx.ctx.flags, "redis_rate_hard")

        ngx.log(ngx.WARN, "[REDIS_RL] HARD limit IP=", ip,
                " count=", count,
                " score=", ngx.ctx.risk_score)

    elseif count > (REDIS_RATE_LIMIT * 0.7) then
        ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_REDIS_SOFT
        table.insert(ngx.ctx.flags, "redis_rate_soft")

        ngx.log(ngx.INFO, "[REDIS_RL] Near limit IP=", ip,
                " count=", count,
                " score=", ngx.ctx.risk_score)
    end

    -- ================= HEADERS =================

    ngx.header["X-RateLimit-Limit"]     = REDIS_RATE_LIMIT
    ngx.header["X-RateLimit-Remaining"] =
        math.max(0, REDIS_RATE_LIMIT - count)

    return nil
end

return _M