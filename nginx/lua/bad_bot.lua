local _M = {}

-- ================= CONFIG =================

-- 🔥 Scanner / attack tools (hard block)
local scanner_pattern = [[
\b(sqlmap|nikto|nmap|zgrab|masscan|nuclei|dirbuster|gobuster|wfuzz|ffuf|hydra|acunetix|nessus|zap)\b
]]

-- 🛠 Dev tools (allow nhưng tăng risk nhẹ)
local dev_pattern = [[
\b(curl|wget|python-requests|postmanruntime|insomnia|httpie|okhttp)\b
]]

-- ✅ Whitelist UA
local whitelist_pattern = [[
\b(healthchecker|kube-probe|prometheus|uptime|statuscake)\b
]]

-- ✅ Whitelist IP
local WHITELIST_IPS = {
    ["127.0.0.1"] = true,
}

-- 🎯 Risk scoring
local SCORE_EMPTY_UA        = 10
local SCORE_DEV_TOOL        = 5
local SCORE_SHORT_UA        = 15
local SCORE_NON_BROWSER     = 5
local SCORE_SUSPICIOUS_UA   = 20

-- ================= CORE =================

function _M.run()
    -- 🔥 unified IP (sau xff_guard)
    local ip = ngx.ctx.real_ip or ngx.var.remote_addr

    -- init shared context nếu chưa có
    ngx.ctx.risk_score = ngx.ctx.risk_score or 0
    ngx.ctx.flags      = ngx.ctx.flags or {}

    -- ================= WHITELIST =================
    if WHITELIST_IPS[ip] then
        return nil
    end

    local ua = ngx.var.http_user_agent

    -- ================= Tier 0: Missing UA =================
    if not ua or ua == "" then
        ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_EMPTY_UA
        table.insert(ngx.ctx.flags, "empty_ua")

        ngx.log(ngx.WARN, "[BAD_BOT] Missing UA IP=", ip,
                " score=", ngx.ctx.risk_score)

        -- chỉ block nếu method nguy hiểm
        local method = ngx.req.get_method()
        if method ~= "GET" then
            if metric_blocked then metric_blocked:inc(1, {"empty_ua_block"}) end
            return 403
        end

        return nil
    end

    local ua_lower = ua:lower()

    -- ================= Tier 1: Whitelist =================
    if ngx.re.find(ua_lower, whitelist_pattern, "jo") then
        return nil
    end

    -- ================= Tier 2: Scanner (HARD BLOCK) =================
    if ngx.re.find(ua_lower, scanner_pattern, "jo") then
        ngx.log(ngx.WARN, "[BAD_BOT] Scanner BLOCKED: ", ua, " IP=", ip)

        if metric_blocked then metric_blocked:inc(1, {"bad_bot_scanner"}) end
        return 403
    end

    -- ================= Tier 3: Dev tools =================
    if ngx.re.find(ua_lower, dev_pattern, "jo") then
        ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_DEV_TOOL
        table.insert(ngx.ctx.flags, "dev_tool")

        ngx.log(ngx.INFO, "[BAD_BOT] Dev tool detected: ", ua,
                " IP=", ip, " score=", ngx.ctx.risk_score)
    end

    -- ================= Tier 4: Heuristics =================

    -- UA quá ngắn
    if #ua < 10 then
        ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_SHORT_UA
        table.insert(ngx.ctx.flags, "short_ua")

        ngx.log(ngx.WARN, "[BAD_BOT] Short UA: ", ua,
                " IP=", ip, " score=", ngx.ctx.risk_score)
    end

    -- Không giống browser
    if not ngx.re.find(ua_lower, [[(mozilla|chrome|safari|firefox|edge)]], "jo") then
        ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_NON_BROWSER
        table.insert(ngx.ctx.flags, "non_browser")

        ngx.log(ngx.INFO, "[BAD_BOT] Non-browser UA: ", ua,
                " IP=", ip, " score=", ngx.ctx.risk_score)
    end

    -- UA có dấu hiệu obfuscation (random string, entropy cao)
    if ngx.re.find(ua, [[^[A-Za-z0-9]{20,}$]], "jo") then
        ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_SUSPICIOUS_UA
        table.insert(ngx.ctx.flags, "obfuscated_ua")

        ngx.log(ngx.WARN, "[BAD_BOT] Obfuscated UA: ", ua,
                " IP=", ip, " score=", ngx.ctx.risk_score)
    end

    -- ================= FINAL =================
    -- ❗ Không block ở đây → để pipeline quyết định
    return nil
end

return _M