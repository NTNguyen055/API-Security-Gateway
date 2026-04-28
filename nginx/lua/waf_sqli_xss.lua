local _M = {}

local ngx = ngx
local re_find = ngx.re.find
local math_min = math.min

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

local function normalize(input)
    if not input then return "" end

    input = ngx.unescape_uri(input)
    input = ngx.unescape_uri(input)

    input = input:lower()

    input = input:gsub("/%*.-%*/", "")
    input = input:gsub("%s+", " ")

    return input
end

local function check(value, ctx)
    if not value then return false end

    local v = normalize(value)

    if re_find(v, SQLI_PATTERN, "ijo") then
        ctx.security.waf_sqli = true

        local base = 30
        if ctx.security.bad_bot then base = base + 10 end

        ctx.security.risk = math_min((ctx.security.risk or 0) + base, 100)

        ctx.security.signals = ctx.security.signals or {}
        table.insert(ctx.security.signals, "waf_sqli")

        ngx.log(ngx.WARN, "[WAF][SQLi]")
        return true
    end

    if re_find(v, XSS_PATTERN, "ijo") then
        ctx.security.waf_xss = true

        ctx.security.risk = math_min((ctx.security.risk or 0) + 30, 100)

        ctx.security.signals = ctx.security.signals or {}
        table.insert(ctx.security.signals, "waf_xss")

        ngx.log(ngx.WARN, "[WAF][XSS]")
        return true
    end

    return false
end

function _M.run(ctx)
    ctx.security = ctx.security or {}

    -- URI (không include query)
    local uri = ngx.var.uri
    if check(uri, ctx) then return end

    -- QUERY
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

    -- HEADERS
    local headers = ngx.req.get_headers()

    if check(headers["user-agent"], ctx) then return end
    if check(headers["referer"], ctx) then return end

    -- BODY
    local method = ngx.req.get_method()

    if method == "POST" or method == "PUT" then
        ngx.req.read_body()

        local body = ngx.req.get_body_data()

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

        if body then
            if #body > 512 * 1024 then
                body = body:sub(1, 512 * 1024)
            end

            check(body, ctx)
        end
    end
end

return _M