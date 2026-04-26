local _M = {}

local lim

-- ================= DEPENDENCIES =================
local resty_md5 = require "resty.md5"
local resty_str = require "resty.string"

-- ================= CONFIG =================

local RATE  = tonumber(os.getenv("RATE_LIMIT_RPS"))   or 10
local BURST = tonumber(os.getenv("RATE_LIMIT_BURST")) or 20

-- Auto blacklist
local AUTO_BL_THRESHOLD = tonumber(os.getenv("AUTO_BL_THRESHOLD")) or 5
local AUTO_BL_WINDOW    = tonumber(os.getenv("AUTO_BL_WINDOW"))    or 60
local AUTO_BL_DURATION  = tonumber(os.getenv("AUTO_BL_DURATION"))  or 3600

-- Risk scoring
local SCORE_BURST        = 10
local SCORE_HARD_REJECT  = 30

-- Whitelist IP
local WHITELIST_IPS = {
    ["127.0.0.1"] = true,
}

-- ================= HELPERS =================

-- FIX: hash UA để tránh bloat shared memory khi UA biến thiên liên tục
local function hash_ua(ua)
    if not ua or ua == "" then return "empty" end

    local m = resty_md5:new()
    if not m then return "x" end

    m:update(ua)
    local digest = m:final()
    if not digest then return "x" end

    return resty_str.to_hex(digest):sub(1, 8)  -- lấy 8 hex chars là đủ
end

-- ================= LIMITER =================

local function get_limiter()
    if lim then return lim end

    local limit_req = require "resty.limit.req"

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

    -- L1 cache
    local bl_cache = ngx.shared.ip_blacklist
    if bl_cache then
        bl_cache:set(ip, true, AUTO_BL_DURATION)
    end

    -- Async Redis — dùng key prefix chuẩn bl:v1: để khớp ip_blacklist.lua
    ngx.timer.at(0, function(premature, target_ip, duration)
        if premature then return end

        local redis = require "resty.redis"
        local red = redis:new()
        red:set_timeouts(500, 500, 500)

        local ok, err = red:connect("redis", 6379)
        if not ok then
            ngx.log(ngx.ERR, "[AUTO_BL] Redis connect failed: ", err)
            return
        end

        red:set("bl:v1:" .. target_ip, 1, "EX", duration)

        red:set_keepalive(10000, 100)

        ngx.log(ngx.WARN, "[AUTO_BL] BLACKLISTED IP=", target_ip,
                " duration=", duration)
    end, ip, AUTO_BL_DURATION)

    counter_store:set("rl:" .. ip, 0, AUTO_BL_WINDOW)
end

-- ================= CORE =================

function _M.run()
    local limiter = get_limiter()
    if not limiter then return nil end  -- fail-open

    local ip = ngx.ctx.real_ip or ngx.var.remote_addr

    ngx.ctx.risk_score = ngx.ctx.risk_score or 0
    ngx.ctx.flags      = ngx.ctx.flags or {}

    if WHITELIST_IPS[ip] then
        return nil
    end

    -- FIX: hash UA trước khi ghép vào key → tránh shared memory bloat
    local ua = ngx.var.http_user_agent or ""
    local key = ip .. ":" .. hash_ua(ua)

    local delay, err = limiter:incoming(key, true)

    if not delay then
        if err == "rejected" then
            ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_HARD_REJECT
            table.insert(ngx.ctx.flags, "rate_limit_hard")

            ngx.log(ngx.WARN, "[RATE_LIMIT] HARD REJECT IP=", ip,
                    " score=", ngx.ctx.risk_score)

            auto_blacklist(ip)

            return nil
        end

        ngx.log(ngx.ERR, "[RATE_LIMIT] Error: ", err)
        return nil
    end

    if delay > 0 then
        ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_BURST
        table.insert(ngx.ctx.flags, "rate_limit_burst")

        ngx.log(ngx.INFO, "[RATE_LIMIT] Burst detected IP=", ip,
                " delay=", string.format("%.3f", delay),
                " score=", ngx.ctx.risk_score)
    end

    return nil
end

return _M
