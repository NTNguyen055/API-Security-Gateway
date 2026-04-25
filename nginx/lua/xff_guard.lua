local _M = {}

--[[
    XFF SPOOFING GUARD — Trust Boundary Edition
    ---------------------------------------------
    Nguyên tắc vàng:
    ┌─────────────────────────────────────────────────────┐
    │ XFF chỉ đáng tin khi request đến từ trusted proxy  │
    │ Nếu không → XFF là untrusted → client đang spoof   │
    └─────────────────────────────────────────────────────┘

    3 case thực tế:
    ┌──────────────────────────────────┬────────────────────────┐
    │ Request từ Internet trực tiếp   │ ❌ IGNORE / FLAG XFF   │
    │ Request từ trusted proxy         │ ✅ TRUST + validate XFF │
    │ XFF xuất hiện không qua proxy   │ 🚨 SPOOF → ban          │
    └──────────────────────────────────┴────────────────────────┘

    Lý do KHÔNG check "real_ip ∈ XFF":
    Client → Cloudflare(172.x) → OpenResty
    → remote_addr = 172.x.x.x
    → XFF = "client_ip"
    → real_ip KHÔNG nằm trong XFF → false positive!
]]

-- ✅ Chỉ trust explicit proxy — KHÔNG trust toàn bộ private range
local TRUSTED_PROXIES = {
    ["127.0.0.1"]  = true,  -- localhost
    ["172.17.0.1"] = true,  -- Docker bridge
    ["172.18.0.1"] = true,  -- Docker compose network
    -- Thêm IP ALB/CloudFront nếu có
}

-- Scoring
local SCORE_XFF_SPOOF     = 50  -- client gửi XFF trực tiếp (không qua trusted proxy)
local SCORE_XFF_ANOMALY   = 20  -- chain có vấn đề về format/structure
local SCORE_BAN_THRESHOLD = 50  -- đủ điểm → ban
local BAN_DURATION        = 300 -- giây (5 phút)
local MAX_HOP_COUNT       = 10  -- chain quá dài → suspicious

-- Validate format IPv4
local function is_valid_ip(ip)
    return ngx.re.find(ip,
        [[^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$]], "jo") ~= nil
end

-- Private IP range (suspicious nếu xuất hiện trong XFF chain)
local function is_private_ip(ip)
    return ngx.re.find(ip,
        [[^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.)]], "jo") ~= nil
end

-- Đếm hop
local function count_hops(xff)
    local count = 0
    for _ in xff:gmatch("[^,]+") do count = count + 1 end
    return count
end

-- Detect duplicate IP trong chain
local function has_duplicate_ip(xff)
    local seen = {}
    for part in xff:gmatch("[^,]+") do
        local ip = part:gsub("%s+", "")
        if seen[ip] then return true end
        seen[ip] = true
    end
    return false
end

-- Validate toàn bộ chain (format + private IP anomaly)
local function validate_xff_chain(xff, score, reasons)
    -- Hop count quá lớn
    if count_hops(xff) > MAX_HOP_COUNT then
        score = score + SCORE_XFF_ANOMALY
        table.insert(reasons, "max_hop")
    end

    -- Duplicate IP
    if has_duplicate_ip(xff) then
        score = score + SCORE_XFF_ANOMALY
        table.insert(reasons, "duplicate_ip")
    end

    -- Từng IP trong chain
    for part in xff:gmatch("[^,]+") do
        local ip = part:gsub("%s+", "")

        -- Format không hợp lệ
        if not is_valid_ip(ip) then
            score = score + SCORE_XFF_ANOMALY
            table.insert(reasons, "invalid_chain_ip=" .. ip)
            break
        end

        -- Client IP là private → suspicious (attacker inject private IP)
        if is_private_ip(ip) then
            score = score + SCORE_XFF_ANOMALY
            table.insert(reasons, "private_in_chain=" .. ip)
            break
        end
    end

    return score
end

-- Ghi ban vào Redis non-blocking
local function ban_ip_redis(ip, duration, reason)
    local ok, err = ngx.timer.at(0, function(premature, t_ip, dur, rsn)
        if premature then return end
        local redis = require "resty.redis"
        local red = redis:new()
        red:set_timeouts(500, 500, 500)
        local conn_ok, conn_err = red:connect("redis", 6379)
        if not conn_ok then
            ngx.log(ngx.ERR, "[XFF_GUARD] Redis connect failed: ", conn_err)
            return
        end
        red:sadd("blacklist_ips", t_ip)
        red:set("bl_time:"   .. t_ip, ngx.time(), "EX", dur)
        red:set("bl_reason:" .. t_ip, rsn,        "EX", dur)
        red:set_keepalive(10000, 100)
        ngx.log(ngx.WARN, "[XFF_GUARD] Banned: ", t_ip,
                " reason=", rsn, " duration=", dur, "s")
    end, ip, duration, reason)

    if not ok then
        ngx.log(ngx.ERR, "[XFF_GUARD] Timer error: ", err)
    end
end

function _M.run()
    local real_ip = ngx.var.remote_addr
    local xff     = ngx.var.http_x_forwarded_for

    -- Không có XFF → bình thường
    if not xff or xff == "" then
        return nil
    end

    local score   = 0
    local reasons = {}

    -- ✅ CORE LOGIC: Trust boundary check
    local is_from_trusted_proxy = TRUSTED_PROXIES[real_ip]

    if not is_from_trusted_proxy then
        --[[
            Client gửi XFF trực tiếp đến OpenResty mà không qua trusted proxy
            → Đây là XFF untrusted → spoof attempt
            Ví dụ: curl -H "X-Forwarded-For: 1.2.3.4" https://...
        ]]
        score = score + SCORE_XFF_SPOOF
        table.insert(reasons, "untrusted_xff")

        ngx.log(ngx.WARN,
            "[XFF_GUARD] Untrusted XFF! ",
            "real_ip=", real_ip,
            " xff=", xff,
            " score=", score
        )
    else
        --[[
            Request đến từ trusted proxy → XFF có giá trị
            Validate nội dung chain để phát hiện inject
        ]]
        -- Validate IP đầu tiên (client IP do proxy ghi)
        local first_ip = xff:match("^%s*([^,]+)%s*")
        if first_ip then
            first_ip = first_ip:gsub("%s+", "")
            if not is_valid_ip(first_ip) then
                score = score + SCORE_XFF_ANOMALY
                table.insert(reasons, "invalid_client_ip=" .. first_ip)
            end
        end

        -- Validate toàn bộ chain
        score = validate_xff_chain(xff, score, reasons)
    end

    -- Score = 0 → pass
    if score == 0 then
        return nil
    end

    -- Log
    local reason_str = table.concat(reasons, "|")
    ngx.log(ngx.WARN,
        "[XFF_GUARD] Anomaly IP=", real_ip,
        " score=", score, "/", SCORE_BAN_THRESHOLD,
        " reasons=", reason_str,
        " xff=", xff
    )

    if metric_blocked then
        metric_blocked:inc(1, {"xff_spoof"})
    end

    -- ── SCORING DECISION ──
    if score >= SCORE_BAN_THRESHOLD then
        -- Tránh spam Redis: chỉ ban nếu chưa có trong L1 cache
        local bl_cache = ngx.shared.ip_blacklist
        if bl_cache and not bl_cache:get(real_ip) then
            bl_cache:set(real_ip, true, BAN_DURATION)
            ban_ip_redis(real_ip, BAN_DURATION, reason_str)
        end

        -- Sanitize trước khi block
        ngx.req.set_header("X-Forwarded-For", real_ip)
        ngx.req.set_header("X-Real-IP", real_ip)

        return 403
    else
        -- Anomaly nhẹ → normalize header, KHÔNG block (tránh false positive)
        ngx.req.set_header("X-Forwarded-For", real_ip)
        ngx.req.set_header("X-Real-IP", real_ip)

        ngx.log(ngx.INFO,
            "[XFF_GUARD] Low score, sanitized only. IP=", real_ip,
            " score=", score
        )
        return nil
    end
end

return _M
