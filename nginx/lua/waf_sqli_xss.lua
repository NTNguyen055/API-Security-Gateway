local _M = {}

local ngx      = ngx
local re_find  = ngx.re.find
local math_min = math.min

-- =============================================================================
-- PATTERNS — viết trên một dòng, không có newline trong chuỗi pattern
-- FIX: multiline pattern với newline thực sự gây compile error trong ngx.re
-- =============================================================================

-- SQLi: union/select, DML, tautology, comment, time-based blind, stacked queries
local SQLI_PATTERN = table.concat({
    [[\bunion\b.{0,20}\bselect\b]],
    [[\bselect\b.{0,30}\bfrom\b]],
    [[\b(?:insert|delete|drop|truncate|update)\b.{0,20}\b(?:into|from|table|set)\b]],
    [[\bor\b\s+['"]?1['"]?\s*=\s*['"]?1]],    -- OR 1=1, OR '1'='1'
    [[\band\b\s+['"]?1['"]?\s*=\s*['"]?1]],   -- AND 1=1
    [[--\s|#\s|/\*]],                          -- SQL comments
    [[\bsleep\s*\(]],                          -- time-based blind
    [[\bbenchmark\s*\(]],                      -- time-based blind MySQL
    [[\bwaitfor\s+delay\b]],                   -- time-based blind MSSQL
    [[\bload_file\s*\(]],                      -- file read
    [[\binto\s+(?:outfile|dumpfile)\b]],       -- file write
    [[\bexec(?:ute)?\s*\(]],                   -- exec / execute
    [[\bxp_cmdshell\b]],                       -- MSSQL command exec
    [[;\s*(?:drop|insert|delete|update)\b]],   -- stacked queries
}, "|")

-- XSS: tags, event handlers, JS protocol, DOM sinks
local XSS_PATTERN = table.concat({
    [[<\s*script\b]],
    [[javascript\s*:]],
    [[vbscript\s*:]],                              -- IE legacy
    [[on(?:error|load|click|mouseover|focus|blur|keyup|keydown|submit|change|input|resize|scroll)\s*=]], -- event handlers
    [[<\s*(?:svg|img|body|input|link|meta|object|embed|iframe|frame|base)\b[^>]*?on\w+\s*=]],
    [[<\s*iframe\b]],
    [[document\s*\.\s*(?:cookie|write|location)]],
    [[window\s*\.\s*(?:location|open)]],
    [[(?:alert|confirm|prompt)\s*\(]],             -- JS dialog (reflected XSS proof)
    [[&#\s*x?[0-9a-f]+\s*;]],                     -- HTML entity encoding bypass
    [[\\u[0-9a-f]{4}]],                            -- unicode escape bypass
    [[expression\s*\(]],                           -- IE CSS expression
    [[<\s*style\b[^>]*>.*?(?:expression|javascript)]],
}, "|")

-- =============================================================================
-- NORMALIZE — decode encoding layers để chống bypass
-- =============================================================================
local function normalize(input)
    if not input then return "" end

    -- Double URL decode (chống double-encoding attack)
    local ok1, decoded1 = pcall(ngx.unescape_uri, input)
    if ok1 then input = decoded1 end

    local ok2, decoded2 = pcall(ngx.unescape_uri, input)
    if ok2 then input = decoded2 end

    -- Lowercase
    input = input:lower()

    -- Strip SQL comments /* ... */
    input = input:gsub("/%*.-%*/", " ")

    -- Strip HTML comments <!-- ... -->
    input = input:gsub("<!%-%-.-%-%->", " ")

    -- Decode HTML numeric entities &#60; &#x3c; → thay bằng dấu cách
    -- (tránh false positive, nhưng vẫn detect pattern sau decode)
    input = input:gsub("&#x?%x+;", " ")

    -- Normalize whitespace
    input = input:gsub("%s+", " ")

    -- Strip null bytes
    input = input:gsub("%z", "")

    return input
end

-- =============================================================================
-- CHECK — scan một giá trị, trả về true nếu phát hiện attack
-- FIX: set block = true ngay khi detect, không chỉ tăng risk
-- =============================================================================
local function check(value, ctx, source)
    if not value or value == "" then return false end

    -- Giới hạn độ dài để tránh ReDoS
    if #value > 8192 then
        value = value:sub(1, 8192)
    end

    local v = normalize(value)

    -- ── SQLi ──────────────────────────────────────────────────
    if re_find(v, SQLI_PATTERN, "ijo") then
        ctx.security.waf_sqli = true
        ctx.security.block    = true   -- FIX: hard block ngay

        local base = 60
        if ctx.security.bad_bot_scanner then base = math_min(base + 20, 100) end

        ctx.security.risk = math_min((ctx.security.risk or 0) + base, 100)

        ctx.security.signals = ctx.security.signals or {}
        table.insert(ctx.security.signals, "waf_sqli")

        local ip = (ctx.security and ctx.security.client_ip)
                   or ngx.var.realip_remote_addr or ngx.var.remote_addr

        ngx.log(ngx.WARN,
            "[WAF][SQLi] ip=", ip,
            " source=", (source or "unknown"),
            " val=", v:sub(1, 120)   -- log tối đa 120 ký tự để forensics
        )

        if metric_blocked then
            metric_blocked:inc(1, {"waf_sqli"})
        end

        return true
    end

    -- ── XSS ──────────────────────────────────────────────────
    if re_find(v, XSS_PATTERN, "ijo") then
        ctx.security.waf_xss = true
        ctx.security.block   = true   -- FIX: hard block ngay

        ctx.security.risk = math_min((ctx.security.risk or 0) + 60, 100)

        ctx.security.signals = ctx.security.signals or {}
        table.insert(ctx.security.signals, "waf_xss")

        local ip = (ctx.security and ctx.security.client_ip)
                   or ngx.var.realip_remote_addr or ngx.var.remote_addr

        ngx.log(ngx.WARN,
            "[WAF][XSS] ip=", ip,
            " source=", (source or "unknown"),
            " val=", v:sub(1, 120)
        )

        if metric_blocked then
            metric_blocked:inc(1, {"waf_xss"})
        end

        return true
    end

    return false
end

-- =============================================================================
-- SCAN ARGS TABLE — hỗ trợ cả single value và multi-value (array)
-- =============================================================================
local function scan_args(args, ctx)
    for k, v in pairs(args) do
        if type(v) == "table" then
            for _, vv in ipairs(v) do
                if check(tostring(vv), ctx, "query:" .. tostring(k)) then
                    return true
                end
            end
        else
            if check(tostring(v), ctx, "query:" .. tostring(k)) then
                return true
            end
        end
    end
    return false
end

-- =============================================================================
-- MAIN
-- =============================================================================
function _M.run(ctx)
    ctx.security         = ctx.security or {}
    ctx.security.signals = ctx.security.signals or {}

    -- ── 1. URI PATH ───────────────────────────────────────────
    local uri = ngx.var.uri
    if check(uri, ctx, "uri") then return end

    -- ── 2. QUERY STRING ───────────────────────────────────────
    -- Giới hạn số lượng args để tránh parsing abuse
    local args, err = ngx.req.get_uri_args(100)
    if args and scan_args(args, ctx) then return end

    -- ── 3. HEADERS NGUY HIỂM ─────────────────────────────────
    local headers = ngx.req.get_headers()
    if check(headers["user-agent"], ctx, "header:user-agent") then return end
    if check(headers["referer"],    ctx, "header:referer")    then return end
    if check(headers["x-forwarded-for"], ctx, "header:xff")   then return end

    -- ── 4. REQUEST BODY (POST / PUT / PATCH) ──────────────────
    local method = ngx.req.get_method()
    if method ~= "POST" and method ~= "PUT" and method ~= "PATCH" then
        return
    end

    ngx.req.read_body()

    local body = ngx.req.get_body_data()

    -- Body buffer ra file khi vượt client_body_buffer_size
    if not body then
        local file = ngx.req.get_body_file()
        if file then
            local f = io.open(file, "r")
            if f then
                body = f:read(512 * 1024)
                f:close()
            end
        end
    end

    if not body then return end

    -- Cap 512KB để tránh OOM
    if #body > 512 * 1024 then
        body = body:sub(1, 512 * 1024)
    end

    local content_type = (headers["content-type"] or ""):lower()

    -- JSON body: scan raw string (pattern vẫn detect sau normalize)
    if content_type:find("application/json", 1, true) then
        check(body, ctx, "body:json")
        return
    end

    -- Form URL-encoded: parse rồi scan từng field
    if content_type:find("application/x-www-form-urlencoded", 1, true) then
        -- ngx.req.get_post_args() cần body đã được read ở trên
        local post_args, _ = ngx.req.get_post_args(100)
        if post_args then
            scan_args(post_args, ctx)
        else
            check(body, ctx, "body:form")
        end
        return
    end

    -- Multipart hoặc content-type khác: scan raw
    check(body, ctx, "body:raw")
end

return _M
