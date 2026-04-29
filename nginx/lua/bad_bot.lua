local _M = {}

local ngx = ngx
local math_min = math.min

local SCANNERS = {
    "sqlmap", "nikto", "nmap", "zgrab", "masscan", "nuclei", "dirbuster", "gobuster"
}

local HEADLESS = {
    "headless", "headlesschrome", "phantomjs", "selenium", "puppeteer", "playwright"
}

local DEV_TOOLS = {
    "curl", "wget", "python-requests", "postmanruntime", "insomnia", "httpie"
}

local WHITELIST = {
    "googlebot", "bingbot"
}

local function contains_any(str, patterns)
    for i = 1, #patterns do
        if str:find(patterns[i], 1, true) then
            return true
        end
    end
    return false
end

function _M.run(ctx)
    local ip = ngx.var.realip_remote_addr or ngx.var.remote_addr
    local ua = ngx.var.http_user_agent

    ctx.security = ctx.security or {}
    ctx.security.signals = ctx.security.signals or {}

    -- EMPTY UA
    if not ua or ua == "" then
        ctx.security.empty_ua = true

        local base = 20
        if ctx.security.rate_limit_hard then base = base + 15 end
        if ctx.security.waf_sqli or ctx.security.waf_xss then base = base + 20 end

        ctx.security.risk = math_min((ctx.security.risk or 0) + base, 100)

        table.insert(ctx.security.signals, "empty_ua")

        ngx.log(ngx.WARN, "[BAD_BOT] Empty UA IP=", ip)
        return
    end

    local ua_lower = ua:lower()

    -- WHITELIST
    if contains_any(ua_lower, WHITELIST) then
        ctx.security.ua_whitelisted = true
        return
    end

    -- SAFE MOZILLA (không phải bot trá hình)
    if ua:find("Mozilla", 1, true)
       and not contains_any(ua_lower, SCANNERS)
       and not contains_any(ua_lower, HEADLESS)
       and not contains_any(ua_lower, DEV_TOOLS) -- [FIX] Chặn bypass bằng Dev Tools giả danh Mozilla
    then
        ctx.security.ua_normal = true
        return
    end

    -- HEALTH CHECK
    if ua:find("HealthChecker", 1, true) then
        ctx.security.healthcheck = true
        return
    end

    -- SCANNER
    if contains_any(ua_lower, SCANNERS) then
        ctx.security.bad_bot_scanner = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 50, 100)

        table.insert(ctx.security.signals, "bad_bot_scanner")

        ngx.log(ngx.WARN,
            "[BAD_BOT] Scanner UA=", ua,
            " IP=", ip
        )
        return
    end

    -- HEADLESS
    if contains_any(ua_lower, HEADLESS) then
        ctx.security.bad_bot_headless = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 30, 100)

        table.insert(ctx.security.signals, "bad_bot_headless")

        ngx.log(ngx.WARN,
            "[BAD_BOT] Headless UA=", ua,
            " IP=", ip
        )
        return
    end

    -- DEV TOOLS
    if contains_any(ua_lower, DEV_TOOLS) then
        ctx.security.dev_tool = true

        local base = 10
        if ctx.security.rate_limit_hard then base = base + 10 end

        ctx.security.risk = math_min((ctx.security.risk or 0) + base, 100)

        table.insert(ctx.security.signals, "dev_tool")

        ngx.log(ngx.INFO,
            "[BAD_BOT] DevTool UA=", ua,
            " IP=", ip
        )
        return
    end

    ctx.security.ua_unknown = true
end

return _M