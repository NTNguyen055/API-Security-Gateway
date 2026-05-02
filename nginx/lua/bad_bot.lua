local _M = {}

local ngx      = ngx
local math_min = math.min

-- =============================================================================
-- UA LISTS — mở rộng đầy đủ hơn
-- =============================================================================

-- Scanner / exploit tools — hard block
local SCANNERS = {
    -- Web scanners
    "sqlmap", "nikto", "nmap", "zgrab", "masscan",
    "nuclei", "dirbuster", "gobuster", "dirb", "ffuf",
    "wfuzz", "feroxbuster",
    -- Vuln scanners
    "acunetix", "nessus", "openvas", "qualys", "rapid7",
    "burpsuite", "burp suite", "owasp zap", "zaproxy",
    -- Password/brute
    "hydra", "medusa", "patator", "thc-hydra",
    -- Crawlers/scrapers tấn công
    "wpscan", "joomscan", "droopescan",
    -- Generic
    "scanner", "exploit", "attack", "inject",
}

-- Headless browsers — suspicious, tăng risk cao
local HEADLESS = {
    "headlesschrome", "headless chrome",
    "phantomjs", "slimerjs",
    "selenium", "webdriver",
    "puppeteer", "playwright",
    "cypress",
    "zombie.js", "mechanize",
}

-- Dev tools — tăng risk nhẹ, không block
local DEV_TOOLS = {
    "curl/", "wget/",
    "python-requests", "python-urllib",
    "go-http-client", "java/", "okhttp",
    "axios/", "node-fetch", "got/",
    "postmanruntime", "insomnia",
    "httpie", "httpx",
    "libwww-perl", "lwp-trivial",
}

-- Legitimate crawlers — whitelist
local WHITELIST = {
    "googlebot", "bingbot", "slurp",          -- Search engines
    "duckduckbot", "baiduspider", "yandexbot",
    "facebookexternalhit", "twitterbot",       -- Social previews
    "linkedinbot", "whatsapp", "telegrambot",
    "applebot", "pingdom", "uptimerobot",      -- Monitoring
    "healthchecker",                           -- Internal healthcheck
}

-- =============================================================================
-- HELPERS
-- =============================================================================
local function contains_any(s, patterns)
    for i = 1, #patterns do
        if s:find(patterns[i], 1, true) then
            return patterns[i]   -- NÂNG CẤP: trả về matched pattern để log
        end
    end
    return nil
end

-- =============================================================================
-- MAIN
-- =============================================================================
function _M.run(ctx)
    local ip = (ctx.security and ctx.security.client_ip)
               or ngx.var.realip_remote_addr
               or ngx.var.remote_addr

    local ua = ngx.var.http_user_agent

    ctx.security         = ctx.security or {}
    ctx.security.signals = ctx.security.signals or {}

    -- ── EMPTY UA ─────────────────────────────────────────────
    if not ua or ua == "" then
        ctx.security.empty_ua = true

        local base = 20
        if ctx.security.rate_limit_hard then
            base = math_min(base + 15, 100)
        end
        if ctx.security.waf_sqli or ctx.security.waf_xss then
            base = math_min(base + 20, 100)
        end

        ctx.security.risk = math_min((ctx.security.risk or 0) + base, 100)
        table.insert(ctx.security.signals, "empty_ua")

        ngx.log(ngx.WARN, "[BAD_BOT] Empty UA ip=", ip)
        return
    end

    local ua_lower = ua:lower()

    -- ── WHITELIST ─────────────────────────────────────────────
    if contains_any(ua_lower, WHITELIST) then
        ctx.security.ua_whitelisted = true
        return
    end

    -- ── SCANNER — hard block ngay ─────────────────────────────
    -- FIX: set block = true, không chỉ tăng risk
    local matched_scanner = contains_any(ua_lower, SCANNERS)
    if matched_scanner then
        ctx.security.bad_bot_scanner = true
        ctx.security.block           = true
        ctx.security.risk            = 100

        table.insert(ctx.security.signals, "bad_bot_scanner")

        ngx.log(ngx.WARN,
            "[BAD_BOT] Scanner ip=", ip,
            " matched=", matched_scanner,
            " ua=", ua:sub(1, 120)
        )

        if metric_blocked then
            metric_blocked:inc(1, {"bad_bot_scanner"})
        end
        return
    end

    -- ── HEADLESS BROWSER ─────────────────────────────────────
    local matched_headless = contains_any(ua_lower, HEADLESS)
    if matched_headless then
        ctx.security.bad_bot_headless = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 40, 100)

        table.insert(ctx.security.signals, "bad_bot_headless")

        ngx.log(ngx.WARN,
            "[BAD_BOT] Headless ip=", ip,
            " matched=", matched_headless,
            " ua=", ua:sub(1, 120)
        )
        return
    end

    -- ── SAFE MOZILLA — browser thực sự ───────────────────────
    -- Kiểm tra sau scanner/headless để tránh bỏ qua scanner giả Mozilla
    if ua:find("Mozilla", 1, true) then
        ctx.security.ua_normal = true
        return
    end

    -- ── DEV TOOLS ─────────────────────────────────────────────
    local matched_dev = contains_any(ua_lower, DEV_TOOLS)
    if matched_dev then
        ctx.security.dev_tool = true

        local base = 10
        if ctx.security.rate_limit_hard then
            base = math_min(base + 10, 100)
        end

        ctx.security.risk = math_min((ctx.security.risk or 0) + base, 100)
        table.insert(ctx.security.signals, "dev_tool")

        ngx.log(ngx.INFO,
            "[BAD_BOT] DevTool ip=", ip,
            " matched=", matched_dev,
            " ua=", ua:sub(1, 80)
        )
        return
    end

    -- ── UNKNOWN UA ────────────────────────────────────────────
    -- UA không nhận ra → tăng risk nhẹ để risk_engine xét thêm context
    ctx.security.ua_unknown = true
    ctx.security.risk = math_min((ctx.security.risk or 0) + 5, 100)
    table.insert(ctx.security.signals, "ua_unknown")

    ngx.log(ngx.INFO,
        "[BAD_BOT] Unknown UA ip=", ip,
        " ua=", ua:sub(1, 80)
    )
end

return _M
