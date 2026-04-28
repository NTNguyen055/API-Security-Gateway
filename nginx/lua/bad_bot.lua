local _M = {}

-- ============================================================
-- BAD BOT DETECTION — FINAL (LOW OVERHEAD + ADAPTIVE)
-- ============================================================

local ngx = ngx
local math_min = math.min

-- ============================================================
-- PATTERNS (LOW-COST STRING MATCH FIRST)
-- ============================================================

-- dùng table thay vì regex cho fast-path
local SCANNERS = {
    "sqlmap", "nikto", "nmap", "zgrab", "masscan", "nuclei", "dirbuster", "gobuster"
}

local HEADLESS = {
    "headless", "phantomjs", "selenium", "puppeteer", "playwright"
}

local DEV_TOOLS = {
    "curl", "wget", "python-requests", "postmanruntime", "insomnia", "httpie"
}

-- ============================================================
-- FAST MATCH (NO REGEX)
-- ============================================================

local function contains_any(str, patterns)
    for i = 1, #patterns do
        if str:find(patterns[i], 1, true) then
            return true
        end
    end
    return false
end

-- ============================================================
-- MAIN
-- ============================================================

function _M.run(ctx)
    local ip = ngx.var.remote_addr
    local ua = ngx.var.http_user_agent

    ctx.security = ctx.security or {}

    -- ========================================================
    -- EMPTY UA
    -- ========================================================
    if not ua or ua == "" then
        ctx.security.empty_ua = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 20, 100)

        ngx.log(ngx.WARN, "[BAD_BOT] Empty UA IP=", ip)

        if metric_blocked then
            metric_blocked:inc(1, {"empty_ua"})
        end

        return
    end

    -- ========================================================
    -- FAST PATH: NORMAL BROWSER CHECK
    -- ========================================================
    -- tránh check nặng nếu là browser phổ biến
    if ua:find("Mozilla", 1, true) then
        ctx.security.ua_normal = true
        return
    end

    -- ========================================================
    -- HEALTH CHECK
    -- ========================================================
    if ua:find("HealthChecker", 1, true) then
        ctx.security.healthcheck = true
        return
    end

    local ua_lower = ua:lower()

    -- ========================================================
    -- SCANNER (HIGH RISK)
    -- ========================================================
    if contains_any(ua_lower, SCANNERS) then
        ctx.security.bad_bot_scanner = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 50, 100)

        ngx.log(ngx.WARN,
            "[BAD_BOT] Scanner UA=", ua,
            " IP=", ip
        )

        if metric_blocked then
            metric_blocked:inc(1, {"bad_bot_scanner"})
        end

        return
    end

    -- ========================================================
    -- HEADLESS (STEALTH BOT)
    -- ========================================================
    if contains_any(ua_lower, HEADLESS) then
        ctx.security.bad_bot_headless = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 30, 100)

        ngx.log(ngx.WARN,
            "[BAD_BOT] Headless UA=", ua,
            " IP=", ip
        )

        return
    end

    -- ========================================================
    -- DEV TOOLS (LOW RISK)
    -- ========================================================
    if contains_any(ua_lower, DEV_TOOLS) then
        ctx.security.dev_tool = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 10, 100)

        ngx.log(ngx.INFO,
            "[BAD_BOT] DevTool UA=", ua,
            " IP=", ip
        )

        return
    end

    -- ========================================================
    -- DEFAULT
    -- ========================================================
    ctx.security.ua_unknown = true
end

return _M