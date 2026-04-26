local _M = {}

-- ================= CONFIG =================

local REDIS_RATE_LIMIT = tonumber(os.getenv("REDIS_RATE_LIMIT")) or 30
local REDIS_RL_WINDOW  = tonumber(os.getenv("REDIS_RL_WINDOW"))  or 60

local SCORE_REDIS_SOFT = 10
local SCORE_REDIS_HARD = 25

local REDIS_DOWN_TTL = 5

local MAX_KEYS_PER_IP = 100

-- ================= SKIP =================

local function is_safe_path(uri)
    if not uri then return false end

    return uri:find("^/health")
        or uri:find("^/static")
        or uri:find("^/media")
end

-- ================= REDIS =================

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

-- ================= LUA SCRIPT =================
-- sliding window (approx bằng 2 bucket)

local REDIS_SCRIPT = [[
local key = KEYS[1]
local key_prev = KEYS[2]

local limit = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local now = tonumber(ARGV[3])

local current = redis.call("GET", key)
if not current then current = 0 else current = tonumber(current) end

local prev = redis.call("GET", key_prev)
if not prev then prev = 0 else prev = tonumber(prev) end

local weight = (window - (now % window)) / window
local total = current + (prev * weight)

if total >= limit then
    return {0, total}
end

current = redis.call("INCR", key)
if current == 1 then
    redis.call("EXPIRE", key, window)
end

return {1, total}
]]

-- ================= CORE =================

function _M.run()
    local ip  = ngx.ctx.real_ip or ngx.var.remote_addr
    local uri = ngx.var.uri

    ngx.ctx.risk_score = ngx.ctx.risk_score or 0
    ngx.ctx.flags      = ngx.ctx.flags or {}

    if is_safe_path(uri) then
        return nil
    end

    local red, err = get_redis()
    if not red then
        ngx.log(ngx.WARN, "[REDIS_RL] Redis down → fallback")

        -- 🔥 fallback: tăng risk nhẹ thay vì bỏ qua
        ngx.ctx.risk_score = ngx.ctx.risk_score + 5
        table.insert(ngx.ctx.flags, "redis_down")

        return nil
    end

    local now = ngx.time()
    local window = REDIS_RL_WINDOW

    local curr_bucket = math.floor(now / window)
    local prev_bucket = curr_bucket - 1

    local key      = "rrl:" .. ip .. ":" .. curr_bucket
    local key_prev = "rrl:" .. ip .. ":" .. prev_bucket

    local res, script_err = red:eval(
        REDIS_SCRIPT, 2,
        key, key_prev,
        REDIS_RATE_LIMIT,
        window,
        now
    )

    red:set_keepalive(10000, 100)

    if not res then
        ngx.log(ngx.ERR, "[REDIS_RL] Script error: ", script_err)
        return nil
    end

    local allowed = res[1]
    local total   = res[2]

    ngx.log(ngx.INFO,
        "[REDIS_RL] IP=", ip,
        " total=", total, "/", REDIS_RATE_LIMIT)

    -- ================= DECISION =================

    if allowed == 0 then
        ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_REDIS_HARD
        table.insert(ngx.ctx.flags, "redis_rate_hard")

        ngx.log(ngx.WARN, "[REDIS_RL] HARD limit IP=", ip)

    elseif total > (REDIS_RATE_LIMIT * 0.7) then
        ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_REDIS_SOFT
        table.insert(ngx.ctx.flags, "redis_rate_soft")
    end

    -- ================= HEADERS =================

    ngx.header["X-RateLimit-Limit"] = REDIS_RATE_LIMIT
    ngx.header["X-RateLimit-Remaining"] =
        math.max(0, REDIS_RATE_LIMIT - total)

    return nil
end

return _M