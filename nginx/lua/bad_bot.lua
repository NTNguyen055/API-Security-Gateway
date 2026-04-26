local _M = {}

-- ================= CONFIG =================

local MAX_UA_LENGTH = 512

-- 🔥 Scanner / attack tools (improved)
local scanner_pattern = [[
(sqlmap|nikto|nmap|zgrab|masscan|nuclei|
dirbuster|gobuster|wfuzz|ffuf|hydra|
acunetix|nessus|zap)
]]

-- Dev tools
local dev_pattern = [[
(curl|wget|python-requests|postmanruntime|
insomnia|httpie|okhttp)
]]

-- Legit bots
local whitelist_pattern = [[
(healthchecker|kube-probe|prometheus|
uptime|statuscake|googlebot|bingbot)
]]

-- Browser signature
local browser_pattern = [[
(mozilla|chrome|safari|firefox|edge|opera|mobile)
]]

local WHITELIST_IPS = {
    ["127.0.0.1"] = true,
}

-- Risk scoring
local SCORE_EMPTY_UA        = 10
local SCORE_DEV_TOOL        = 5
local SCORE_SHORT_UA        = 10   -- giảm từ 15
local SCORE_NON_BROWSER     = 3    -- giảm từ 5
local SCORE_SUSPICIOUS_UA   = 20
local SCORE_SCANNER         = 40   -- 🔥 không block ngay

-- ================= NORMALIZE =================

local function normalize_ua(ua)
    if not ua then return "" end

    -- limit size
    if #ua > MAX_UA_LENGTH then
        ua = ua:sub(1, MAX_UA_LENGTH)
    end

    -- remove control chars
    ua = ua:gsub("[%c]", "")

    -- collapse spaces
    ua = ua:gsub("%s+", " ")

    return ua:lower()
end

-- ================= CORE =================

function _M.run()
    local ip = ngx.ctx.real_ip or ngx.var.remote_addr

    ngx.ctx.risk_score = ngx.ctx.risk_score or 0
    ngx.ctx.flags      = ngx.ctx.flags or {}

    if WHITELIST_IPS[ip] then
        return nil
    end

    local ua = ngx.var.http_user_agent

    -- ================= EMPTY =================
    if not ua or ua == "" then
        ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_EMPTY_UA
        table.insert(ngx.ctx.flags, "empty_ua")

        local method = ngx.req.get_method()

        if method ~= "GET" and method ~= "HEAD" then
            return 403
        end

        return nil
    end

    ua = normalize_ua(ua)

    -- ================= WHITELIST =================
    if ngx.re.find(ua, whitelist_pattern, "jo") then
        return nil
    end

    -- ================= SCANNER =================
    if ngx.re.find(ua, scanner_pattern, "jo") then
        ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_SCANNER
        table.insert(ngx.ctx.flags, "scanner")

        ngx.log(ngx.WARN, "[BAD_BOT] Scanner detected IP=", ip, " UA=", ua)
    end

    -- ================= DEV TOOL =================
    if ngx.re.find(ua, dev_pattern, "jo") then
        ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_DEV_TOOL
        table.insert(ngx.ctx.flags, "dev_tool")
    end

    -- ================= HEURISTICS =================

    if #ua < 10 then
        ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_SHORT_UA
        table.insert(ngx.ctx.flags, "short_ua")
    end

    -- chỉ áp dụng non-browser cho POST/API
    local method = ngx.req.get_method()
    if method ~= "GET" then
        if not ngx.re.find(ua, browser_pattern, "jo") then
            ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_NON_BROWSER
            table.insert(ngx.ctx.flags, "non_browser")
        end
    end

    -- obfuscation
    if ngx.re.find(ua, [[^[a-z0-9\-_]{20,}$]], "jo") then
        ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_SUSPICIOUS_UA
        table.insert(ngx.ctx.flags, "obfuscated_ua")
    end

    return nil
end

return _M