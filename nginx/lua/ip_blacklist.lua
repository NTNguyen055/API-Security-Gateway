local _M = {}

local redis = require "resty.redis"

-- ================= CONFIG =================
local REDIS_HOST = os.getenv("REDIS_HOST") or "redis"  -- ✅ FIX: env-driven
local REDIS_PORT = tonumber(os.getenv("REDIS_PORT")) or 6379
local REDIS_AUTH = os.getenv("REDIS_PASSWORD")         -- ✅ THÊM: auth support

local REDIS_TIMEOUT  = 100

local REDIS_DOWN_TTL = 5
local NEG_CACHE_TTL  = 120
local POS_CACHE_TTL  = 600

local REDIS_KEY_PREFIX = "bl:v1:"

local LOG_TTL = 10

-- ================= HELPERS =================

local function is_valid_ip(ip)
    if not ip then return false end
    return ngx.re.find(ip,
        [[^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$]], "jo") ~= nil
end

-- ================= REDIS =================
local function get_redis()
    local cb = ngx.shared.redis_down
    if cb and cb:get("down") then
        return nil, "circuit_open"
    end

    local red = redis:new()
    red:set_timeouts(REDIS_TIMEOUT, REDIS_TIMEOUT, REDIS_TIMEOUT)

    local ok, err = red:connect(REDIS_HOST, REDIS_PORT)
    if not ok then
        if cb then cb:set("down", true, REDIS_DOWN_TTL) end
        return nil, err
    end

    -- ✅ THÊM: authenticate nếu Redis có password
    if REDIS_AUTH and REDIS_AUTH ~= "" then
        local auth_ok, auth_err = red:auth(REDIS_AUTH)
        if not auth_ok then
            ngx.log(ngx.ERR, "[BLACKLIST] Redis auth failed: ", auth_err)
            red:close()
            return nil, "auth_failed"
        end
    end

    return red, nil
end

-- ================= LOG GUARD =================
local function log_once(key, msg)
    local dict = ngx.shared.limit_req_store
    if not dict then return end
    local ok, _ = dict:add(key, true, LOG_TTL)
    if ok then ngx.log(ngx.WARN, msg) end
end

-- ================= CORE =================
function _M.run()
    local ip = ngx.ctx.real_ip or ngx.var.remote_addr

    if not is_valid_ip(ip) then
        ngx.log(ngx.WARN, "[BLACKLIST] Invalid IP: ", ip)
        return nil
    end

    ngx.ctx.risk_score = ngx.ctx.risk_score or 0
    ngx.ctx.flags      = ngx.ctx.flags or {}

    local cache = ngx.shared.ip_blacklist
    if not cache then
        ngx.log(ngx.ERR, "[BLACKLIST] Missing shared dict ip_blacklist")
        return nil
    end

    -- ================= L1 CACHE =================
    local cached = cache:get(ip)
    if cached ~= nil then
        if cached then
            return 403
        else
            return nil
        end
    end

    -- ================= REDIS LOOKUP =================
    local red, err = get_redis()
    if not red then
        log_once("redis_down", "[BLACKLIST] Redis unavailable: " .. (err or "unknown"))
        cache:set(ip, false, 10)
        return nil
    end

    local key = REDIS_KEY_PREFIX .. ip
    local res, rerr = red:get(key)

    if rerr then
        ngx.log(ngx.ERR, "[BLACKLIST] Redis GET error: ", rerr)
        red:set_keepalive(10000, 100)
        cache:set(ip, false, 10)
        return nil
    end

    red:set_keepalive(10000, 100)

    -- ================= DECISION =================
    if res and res ~= ngx.null then
        cache:set(ip, true, POS_CACHE_TTL)
        log_once("bl:" .. ip, "[BLACKLIST] Blocked IP: " .. ip)

        if metric_blocked then
            metric_blocked:inc(1, {"ip_blacklist"})
        end

        return 403
    else
        cache:set(ip, false, NEG_CACHE_TTL)
        return nil
    end
end

return _M
