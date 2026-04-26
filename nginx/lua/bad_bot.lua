local _M = {}

-- ================= CONFIG =================

-- 🔥 Scanner / attack tools (HARD BLOCK)
local scanner_pattern = [[\b(sqlmap|nikto|nmap|zgrab|masscan|nuclei|dirbuster|gobuster|wfuzz|ffuf|hydra|acunetix|nessus|zap)\b]]

-- 🛠 Dev tools
local dev_pattern = [[\b(curl|wget|python-requests|postmanruntime|insomnia|httpie|okhttp)\b]]

-- ✅ Legit bots / monitoring
local whitelist_pattern = [[\b(healthchecker|kube-probe|prometheus|uptime|statuscake|googlebot|bingbot)\b]]

-- ✅ Browser signature (mạnh hơn)
local browser_pattern = [[(mozilla|chrome|safari|firefox|edge|opera|mobile)]]

-- ✅ IP whitelist
local WHITELIST_IPS = {
    ["127.0.0.1"] = true,
}

-- 🎯 Risk scoring
local SCORE_EMPTY_UA        = 10
local SCORE_DEV_TOOL        = 5
local SCORE_SHORT_UA        = 15
local SCORE_NON_BROWSER     = 5
local SCORE_SUSPICIOUS_UA   = 20

-- ================= HELPERS =================

local function normalize_ua(ua)
    if not ua then return "" end

    -- 🔥 truncate để tránh log spam / memory abuse
    if #ua > 256 then
        return ua:sub(1, 256)
    end

    return ua
end

-- ================= CORE =================

function _M.run()
    local ip = ngx.ctx.real_ip or ngx.var.remote_addr

    ngx.ctx.risk_score = ngx.ctx.risk_score or 0
    ngx.ctx.flags      = ngx.ctx.flags or {}

    -- ================= WHITELIST IP =================
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

        local method = ngx.req.get_method()

        -- 🔥 chỉ block method nguy hiểm
        if method ~= "GET" and method ~= "HEAD" then
            if metric_blocked then metric_blocked:inc(1, {"empty_ua_block"}) end
            return 403
        end

        return nil
    end

    -- normalize
    ua = normalize_ua(ua)
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

        ngx.log(ngx.INFO, "[BAD_BOT] Dev tool: ", ua,
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

    -- Không phải browser
    if not ngx.re.find(ua_lower, browser_pattern, "jo") then
        ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_NON_BROWSER
        table.insert(ngx.ctx.flags, "non_browser")

        ngx.log(ngx.INFO, "[BAD_BOT] Non-browser: ", ua,
                " IP=", ip, " score=", ngx.ctx.risk_score)
    end

    -- 🔥 Obfuscation detection (improved)
    if ngx.re.find(ua, [[^[A-Za-z0-9\-_]{20,}$]], "jo") then
        ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_SUSPICIOUS_UA
        table.insert(ngx.ctx.flags, "obfuscated_ua")

        ngx.log(ngx.WARN, "[BAD_BOT] Obfuscated UA: ", ua,
                " IP=", ip, " score=", ngx.ctx.risk_score)
    end

    -- ================= FINAL =================
    return nil
end

return _M