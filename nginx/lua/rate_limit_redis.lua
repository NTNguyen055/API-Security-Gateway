local _M = {}

--[[
    DISTRIBUTED RATE LIMIT — Redis Sliding Window
    -----------------------------------------------
    Khác biệt so với rate_limit.lua (shared memory):
    - Shared memory: mỗi Nginx worker có counter riêng → không đồng bộ khi scale
    - Redis: counter tập trung → chính xác 100% dù có nhiều instance

    Thuật toán: Sliding Window Counter dùng Redis INCR + EXPIRE
    - Mỗi IP có 1 key: "rrl:{ip}:{window}"  (window = unix_time / window_size)
    - INCR mỗi request, EXPIRE tự reset sau window_size giây
    - Non-blocking: dùng lua-resty-redis với connection pool
]]

local REDIS_RATE_LIMIT = tonumber(os.getenv("REDIS_RATE_LIMIT")) or 30  -- req/window
local REDIS_RL_WINDOW  = tonumber(os.getenv("REDIS_RL_WINDOW"))  or 60  -- giây

-- Script Lua chạy atomic trên Redis (tránh race condition)
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

local function get_redis()
    local redis = require "resty.redis"
    local red = redis:new()
    red:set_timeouts(100, 100, 100)  -- timeout ngắn để không block worker

    local ok, err = red:connect("redis", 6379)
    if not ok then
        return nil, err
    end
    return red, nil
end

function _M.run()
    local ip = ngx.var.remote_addr

    local red, err = get_redis()
    if not red then
        ngx.log(ngx.WARN, "[REDIS_RL] Redis unavailable: ", err, " → fail-open")
        return nil  -- fail-open: dùng shared memory rate limit làm backup
    end

    -- Sliding window key: thay đổi mỗi REDIS_RL_WINDOW giây
    local window_id = math.floor(ngx.time() / REDIS_RL_WINDOW)
    local key = "rrl:" .. ip .. ":" .. window_id

    -- Chạy atomic script
    local count, script_err = red:eval(REDIS_SCRIPT, 1, key,
                                       REDIS_RATE_LIMIT, REDIS_RL_WINDOW)

    red:set_keepalive(10000, 100)

    if not count then
        ngx.log(ngx.ERR, "[REDIS_RL] Script error: ", script_err)
        return nil  -- fail-open
    end

    ngx.log(ngx.INFO, "[REDIS_RL] IP=", ip,
            " count=", count, "/", REDIS_RATE_LIMIT)

    if count > REDIS_RATE_LIMIT then
        ngx.log(ngx.WARN, "[REDIS_RL] Rate exceeded IP=", ip,
                " count=", count)
        if metric_blocked then metric_blocked:inc(1, {"redis_rate_limit"}) end
        return 429
    end

    -- Trả về header thông tin cho client
    ngx.header["X-RateLimit-Limit"]     = REDIS_RATE_LIMIT
    ngx.header["X-RateLimit-Remaining"] = math.max(0, REDIS_RATE_LIMIT - count)

    return nil
end

return _M
