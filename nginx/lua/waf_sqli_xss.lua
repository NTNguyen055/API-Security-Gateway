local _M = {}

-- ============================================================
-- WAF SQLi + XSS — FINAL (FAST + LOW OVERHEAD)
-- ============================================================

local ngx = ngx
local re_find = ngx.re.find
local math_min = math.min

-- ============================================================
-- PATTERNS (OPTIMIZED)
-- ============================================================

local SQLI_PATTERN = [[
\bunion\b.{0,10}\bselect\b|
\bselect\b.{0,20}\bfrom\b|
\b(insert|delete|drop|update)\b.{0,10}\b(into|from|table|set)\b|
\bor\b\s+1=1|
(--|#|/\*)
]]

local XSS_PATTERN = [[
<\s*script\b|
javascript\s*:|
onerror\s*=|
onload\s*=|
<\s*svg\b|
<\s*img\b[^>]*onerror|
document\.cookie|
<iframe\b
]]

-- ============================================================
-- NORMALIZE (LIGHTWEIGHT)
-- ============================================================

local function normalize(input)
    if not input then return "" end

    -- decode tối đa 2 lần (anti double encode)
    input = ngx.unescape_uri(input)
    input = ngx.unescape_uri(input)

    input = input:lower()

    -- remove SQL comments (nhẹ hơn)
    input = input:gsub("/%*.-%*/", "")

    return input
end

-- ============================================================
-- CHECK (EARLY EXIT)
-- ============================================================

local function check(value, ctx)
    if not value then return false end

    local v = normalize(value)

    -- SQLi
    if re_find(v, SQLI_PATTERN, "ijo") then
        ctx.security.waf_sqli = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 40, 100)

        ngx.log(ngx.WARN, "[WAF][SQLi]")
        return true
    end

    -- XSS
    if re_find(v, XSS_PATTERN, "ijo") then
        ctx.security.waf_xss = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 35, 100)

        ngx.log(ngx.WARN, "[WAF][XSS]")
        return true
    end

    return false
end

-- ============================================================
-- MAIN
-- ============================================================

function _M.run(ctx)
    ctx.security = ctx.security or {}

    -- ========================================================
    -- 1. URI
    -- ========================================================
    local uri = ngx.var.request_uri
    if check(uri, ctx) then return end

    -- ========================================================
    -- 2. QUERY PARAMS
    -- ========================================================
    local args = ngx.req.get_uri_args()

    for _, v in pairs(args) do
        if type(v) == "table" then
            for _, vv in ipairs(v) do
                if check(vv, ctx) then return end
            end
        else
            if check(v, ctx) then return end
        end
    end

    -- ========================================================
    -- 3. BODY (SAFE LIMIT)
    -- ========================================================
    local method = ngx.req.get_method()

    if method == "POST" or method == "PUT" then
        ngx.req.read_body()

        local body = ngx.req.get_body_data()

        if body then
            -- giới hạn 512KB
            if #body > 512 * 1024 then
                body = body:sub(1, 512 * 1024)
            end

            check(body, ctx)
        end
    end
end

return _M