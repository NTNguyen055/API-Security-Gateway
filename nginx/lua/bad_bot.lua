local _M = {}

local scanner_pattern = [[\b(sqlmap|nikto|nmap|zgrab|masscan|nuclei|dirbuster|gobuster)\b]]
local dev_pattern     = [[\b(curl|wget|python-requests|postmanruntime|insomnia|httpie)\b]]

function _M.run()
    local ip = ngx.var.remote_addr
    local ua = ngx.var.http_user_agent or ""

    -- =========================
    -- WHITELIST HEALTH CHECK
    -- =========================
    if ua:find("HealthChecker") or ua:find("curl") then
        return nil
    end

    -- Tier 3: UA rỗng
    if not ua or ua == "" then
        ngx.log(ngx.WARN, "[BAD_BOT] Empty UA IP: ", ip)
        if metric_blocked then metric_blocked:inc(1, {"empty_ua"}) end
        return 403
    end

    local ua_lower = ua:lower()

    -- Tier 1: scanner độc hại
    if ngx.re.find(ua_lower, scanner_pattern, "jo") then
        ngx.log(ngx.WARN, "[BAD_BOT] Scanner blocked: ", ua, " IP: ", ip)
        if metric_blocked then metric_blocked:inc(1, {"bad_bot"}) end
        return 403
    end

    -- Tier 2: dev tools (KHÔNG BLOCK)
    if ngx.re.find(ua_lower, dev_pattern, "jo") then
        ngx.log(ngx.INFO, "[BAD_BOT] Dev tool: ", ua, " IP: ", ip)
        return nil
    end

    -- Tier 4: Accept header check (SAFE VERSION)
    local accept = ngx.var.http_accept

    if not accept then
        -- KHÔNG BLOCK HEALTH CHECK / SYSTEM CALLS
        ngx.log(ngx.WARN, "[BAD_BOT] Missing Accept header (non-critical): ", ip)
        return nil
    end

    return nil
end

return _M