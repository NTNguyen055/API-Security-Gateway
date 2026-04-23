local _M = {}

-- Trả về: status_code nếu cần block, nil nếu cho qua
function _M.run()
    local ip = ngx.var.remote_addr
    local ua = ngx.var.http_user_agent

    -- Tier 3: UA rỗng → 400
    if not ua or ua == "" then
        ngx.log(ngx.WARN, "[BAD_BOT] Empty UA IP: ", ip)
        if metric_blocked then metric_blocked:inc(1, {"empty_ua"}) end
        return 400
    end

    -- Tier 1: scanner độc hại → 403
    local scanners = {
        "sqlmap", "nikto", "nmap", "zgrab",
        "masscan", "nuclei", "dirbuster", "gobuster"
    }
    for _, bot in ipairs(scanners) do
        if ngx.re.find(ua, bot, "ijo") then
            ngx.log(ngx.WARN, "[BAD_BOT] Scanner blocked: ", ua, " IP: ", ip)
            if metric_blocked then metric_blocked:inc(1, {"bad_bot"}) end
            return 403
        end
    end

    -- Tier 2: dev tools → allow + log
    local dev_tools = {
        "curl", "wget", "python-requests",
        "postmanruntime", "insomnia", "httpie"
    }
    for _, tool in ipairs(dev_tools) do
        if ngx.re.find(ua, tool, "ijo") then
            ngx.log(ngx.INFO, "[BAD_BOT] Dev tool: ", ua, " IP: ", ip)
            return nil  -- cho qua
        end
    end

    return nil  -- cho qua
end

return _M
