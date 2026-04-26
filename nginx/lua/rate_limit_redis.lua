local _M = {}

-- ================= DEPENDENCIES =================
local resty_md5 = require "resty.md5"
local resty_str = require "resty.string"

-- ================= CONFIG =================

local REDIS_RATE_LIMIT = tonumber(os.getenv("REDIS_RATE_LIMIT")) or 30
local REDIS_RL_WINDOW  = tonumber(os.getenv("REDIS_RL_WINDOW"))  or 60

-- Risk scoring
local SCORE_REDIS_SOFT = 10
local SCORE_REDIS_HARD = 25

local REDIS_DOWN_TTL = 5

-- ================= HELPERS =================

-- FIX: hash UA để tránh Redis key quá dài → OOM
local function hash_ua(ua)
    if not ua or ua == "" then return "empty" end

    local m = resty_md5:new()
    if not m then return "x" end

    m:update(ua)
    local digest = m:final()
    if not digest then return "x" end

    return resty_str.to_hex(digest):sub(1, 8)
end

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
    local ip = ngx.ctx.real_ip or ngx.var.remote_addr

    ngx.ctx.risk_score = ngx.ctx.risk_score or 0
    ngx.ctx.flags      = ngx.ctx.flags or {}

    if ngx.ctx.flags and table.concat(ngx.ctx.flags, ","):find("rate_limit_hard") then
        return nil
    end

    local red, err = get_redis()
    if not red then
        ngx.log(ngx.WARN, "[REDIS_RL] Redis unavailable: ", err, " → skip")
        return nil
    end

    -- FIX: hash UA trước khi ghép vào key → tránh Redis key dài → OOM
    local ua = ngx.var.http_user_agent or ""
    local window_id = math.floor(ngx.time() / REDIS_RL_WINDOW)
    local key = "rrl:" .. ip .. ":" .. hash_ua(ua) .. ":" .. window_id

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
