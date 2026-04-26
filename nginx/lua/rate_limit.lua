local _M = {}

local lim

-- ================= DEPENDENCIES =================
local limit_req = require "resty.limit.req"

-- ================= CONFIG =================

local RATE  = tonumber(os.getenv("RATE_LIMIT_RPS"))   or 10
local BURST = tonumber(os.getenv("RATE_LIMIT_BURST")) or 20

local AUTO_BL_THRESHOLD = tonumber(os.getenv("AUTO_BL_THRESHOLD")) or 5
local AUTO_BL_WINDOW    = tonumber(os.getenv("AUTO_BL_WINDOW"))    or 60
local AUTO_BL_DURATION  = tonumber(os.getenv("AUTO_BL_DURATION"))  or 3600

local SCORE_BURST        = 10
local SCORE_HARD_REJECT  = 30

local MAX_UA_LENGTH = 512

local WHITELIST_IPS = {
    ["127.0.0.1"] = true,
}

-- ================= SKIP PATH =================

local function is_safe_path(uri)
    if not uri then return false end

    return uri:find("^/health")
        or uri:find("^/static")
        or uri:find("^/media")
end

-- ================= LIMITER =================

local function get_limiter()
    if lim then return lim end

    local l, err = limit_req.new("limit_req_store", RATE, BURST)
    if not l then
        ngx.log(ngx.ERR, "[RATE_LIMIT] Init failed: ", err)
        return nil
    end

    lim = l
    return lim
end

-- ================= AUTO BLACKLIST =================

local function auto_blacklist(ip)
    local counter_store = ngx.shared.rl_counter
    if not counter_store then return end

    local count, err = counter_store:incr("rl:" .. ip, 1, 0, AUTO_BL_WINDOW)
    if not count then
        ngx.log(ngx.ERR, "[AUTO_BL] Counter error: ", err)
        return
    end

    ngx.log(ngx.INFO, "[AUTO_BL] IP=", ip,
            " reject_count=", count, "/", AUTO_BL_THRESHOLD)

    if count < AUTO_BL_THRESHOLD then
        return
    end

    local bl_cache = ngx.shared.ip_blacklist
    if bl_cache then
        bl_cache:set(ip, true, AUTO_BL_DURATION)
    end

    ngx.timer.at(0, function(premature, target_ip, duration)
        if premature then return end

        local redis = require "resty.redis"
        local red = redis:new()
        red:set_timeouts(500, 500, 500)

        local ok, err = red:connect("redis", 6379)
        if ok then
            red:set("bl:v1:" .. target_ip, 1, "EX", duration)
            red:set_keepalive(10000, 100)
        end
    end, ip, AUTO_BL_DURATION)

    counter_store:set("rl:" .. ip, 0, AUTO_BL_WINDOW)
end

-- ================= CORE =================

function _M.run()
    local limiter = get_limiter()
    if not limiter then return nil end

    local ip  = ngx.ctx.real_ip or ngx.var.remote_addr
    local uri = ngx.var.uri

    ngx.ctx.risk_score = ngx.ctx.risk_score or 0
    ngx.ctx.flags      = ngx.ctx.flags or {}

    if WHITELIST_IPS[ip] then
        return nil
    end

    -- ✅ skip safe endpoints
    if is_safe_path(uri) then
        return nil
    end

    -- 🔥 FIX: limit theo IP only
    local key = ip

    local delay, err = limiter:incoming(key, true)

    if not delay then
        if err == "rejected" then
            ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_HARD_REJECT
            table.insert(ngx.ctx.flags, "rate_limit_hard")

            ngx.log(ngx.WARN, "[RATE_LIMIT] HARD REJECT IP=", ip)

            -- 🔥 chỉ auto-ban nếu POST (giảm false positive)
            if ngx.req.get_method() ~= "GET" then
                auto_blacklist(ip)
            end

            return nil
        end

        ngx.log(ngx.ERR, "[RATE_LIMIT] Error: ", err)
        return nil
    end

    if delay > 0.05 then
        ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_BURST
        table.insert(ngx.ctx.flags, "rate_limit_burst")
    end

    -- ================= HEADERS =================

    ngx.header["X-RateLimit-Limit"] = RATE
    ngx.header["X-RateLimit-Remaining"] = math.max(0, RATE - 1)

    return nil
end

return _M