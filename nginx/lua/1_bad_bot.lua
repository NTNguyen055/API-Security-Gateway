local _M = {}

function _M.run()
    local ua = ngx.var.http_user_agent

    -- Tier 3: UA rỗng → 400 Bad Request
    if not ua or ua == "" then
        ngx.log(ngx.WARN, "[BAD_BOT] Empty User-Agent from: ", ngx.var.remote_addr)
        return ngx.exit(ngx.HTTP_BAD_REQUEST)
    end

    ua = string.lower(ua)

    -- Tier 1: scanner độc hại → 403 + log WARN
    local scanners = {
        "sqlmap", "nikto", "nmap", "zgrab",
        "masscan", "nuclei", "dirbuster", "gobuster"
    }
    for _, bot in ipairs(scanners) do
        if string.find(ua, bot, 1, true) then
            ngx.log(ngx.WARN, "[BAD_BOT] Scanner blocked: ", ua,
                    " IP: ", ngx.var.remote_addr)
            return ngx.exit(ngx.HTTP_FORBIDDEN)
        end
    end

    -- Tier 2: dev tools hợp lệ → cho qua, chỉ ghi log audit
    local dev_tools = {
        "curl", "wget", "python-requests",
        "postmanruntime", "insomnia", "httpie"
    }
    for _, tool in ipairs(dev_tools) do
        if string.find(ua, tool, 1, true) then
            ngx.log(ngx.INFO, "[BAD_BOT] Dev tool allowed: ", ua,
                    " IP: ", ngx.var.remote_addr)
            return  -- tiếp tục pipeline bình thường
        end
    end
end

return _M
