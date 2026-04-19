local _M = {}

function _M.run()
    local ip = ngx.var.remote_addr
    local ua = ngx.var.http_user_agent

    -- Tier 3: UA rỗng → 400
    if not ua or ua == "" then
        ngx.log(ngx.WARN, "[BAD_BOT] Empty UA IP: ", ip)
        return ngx.exit(ngx.HTTP_BAD_REQUEST)
    end

    -- Tier 1: scanner độc hại
    local scanners = {
        "sqlmap", "nikto", "nmap", "zgrab",
        "masscan", "nuclei", "dirbuster", "gobuster"
    }

    for _, bot in ipairs(scanners) do
        if ngx.re.find(ua, bot, "ijo") then
            ngx.log(ngx.WARN, "[BAD_BOT] Scanner blocked: ", ua, " IP: ", ip)
            return ngx.exit(ngx.HTTP_FORBIDDEN)
        end
    end

    -- Tier 2: dev tools (allow + log)
    local dev_tools = {
        "curl", "wget", "python-requests",
        "postmanruntime", "insomnia", "httpie"
    }

    for _, tool in ipairs(dev_tools) do
        if ngx.re.find(ua, tool, "ijo") then
            ngx.log(ngx.INFO, "[BAD_BOT] Dev tool: ", ua, " IP: ", ip)
            return
        end
    end
end

return _M