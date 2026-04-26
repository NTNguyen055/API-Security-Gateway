local _M = {}

-- ================= CONFIG =================

local TRUSTED_PROXIES = {
    ["127.0.0.1"] = true,
}

local MAX_XFF_LENGTH = 512

-- Scoring
local SCORE_XFF_SPOOF     = 50
local SCORE_XFF_ANOMALY   = 20
local SCORE_BAN_THRESHOLD = 50
local BAN_DURATION        = 300

local MAX_HOP_COUNT = 10

-- Redis prefix
local BL_KEY_PREFIX    = "bl:v1:"
local BL_REASON_PREFIX = "bl_reason:v1:"

-- ================= HELPERS =================

local function normalize_ip(ip)
    if not ip then return nil end
    return ip:gsub("%s+", "")
end

local function is_valid_ip(ip)
    return ngx.re.find(ip,
        [[^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$]], "jo") ~= nil
end

local function count_hops(xff)
    local count = 0
    for _ in xff:gmatch("[^,]+") do count = count + 1 end
    return count
end

local function extract_client_ip(xff)
    if not xff then return nil end
    local first = xff:match("^%s*([^,]+)")
    return normalize_ip(first)
end

-- ================= BAN =================

local function ban_ip(ip, duration, reason)
    ngx.timer.at(0, function(premature, t_ip, dur, rsn)
        if premature then return end

        local redis = require "resty.redis"
        local red = redis:new()
        red:set_timeouts(500, 500, 500)

        local ok, err = red:connect("redis", 6379)
        if not ok then
            ngx.log(ngx.ERR, "[XFF] Redis fail: ", err)
            return
        end

        red:set(BL_KEY_PREFIX .. t_ip, 1, "EX", dur)
        red:set(BL_REASON_PREFIX .. t_ip, rsn, "EX", dur)

        red:set_keepalive(10000, 100)
    end, ip, duration, reason)
end

-- ================= CORE =================

function _M.run()
    local remote_ip = ngx.var.remote_addr
    local xff       = ngx.var.http_x_forwarded_for

    -- default IP
    ngx.ctx.real_ip = remote_ip

    -- ================= NO XFF =================
    if not xff or xff == "" then
        return nil
    end

    -- ================= LIMIT SIZE =================
    if #xff > MAX_XFF_LENGTH then
        ngx.log(ngx.WARN, "[XFF] Header too large")
        return 400
    end

    local score   = 0
    local reasons = {}

    local is_trusted = TRUSTED_PROXIES[remote_ip]

    -- ================= UNTRUSTED =================
    if not is_trusted then
        score = score + SCORE_XFF_SPOOF
        table.insert(reasons, "untrusted_xff")

        ngx.log(ngx.WARN,
            "[XFF] Spoof attempt remote_ip=", remote_ip,
            " xff=", xff
        )

    else
        -- ================= TRUSTED FLOW =================

        local client_ip = extract_client_ip(xff)

        if not client_ip or not is_valid_ip(client_ip) then
            score = score + SCORE_XFF_ANOMALY
            table.insert(reasons, "invalid_client_ip")
        else
            ngx.ctx.real_ip = client_ip
        end

        if count_hops(xff) > MAX_HOP_COUNT then
            score = score + SCORE_XFF_ANOMALY
            table.insert(reasons, "too_many_hops")
        end
    end

    -- ================= FINAL =================

    if score == 0 then
        return nil
    end

    local reason_str = table.concat(reasons, "|")

    ngx.ctx.risk_score = (ngx.ctx.risk_score or 0) + score
    table.insert(ngx.ctx.flags, "xff_issue")

    ngx.log(ngx.WARN,
        "[XFF] IP=", ngx.ctx.real_ip,
        " score=", score,
        " reasons=", reason_str
    )

    -- 🔥 FIX: chỉ ban client IP, không ban proxy
    if score >= SCORE_BAN_THRESHOLD and ngx.ctx.real_ip ~= remote_ip then
        local bl_cache = ngx.shared.ip_blacklist
        if bl_cache then
            bl_cache:set(ngx.ctx.real_ip, true, BAN_DURATION)
        end

        ban_ip(ngx.ctx.real_ip, BAN_DURATION, reason_str)

        return 403
    end

    return nil
end

return _M