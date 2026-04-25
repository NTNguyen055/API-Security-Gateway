local _M = {}

-- ================= CONFIG =================

-- SQLi patterns (tối ưu, tránh false positive)
local sqli_pattern = [[
(\bunion\b.{0,20}\bselect\b)|
(\bselect\b.{0,50}\bfrom\b.{0,50}\bwhere\b)|
(\binsert\b.{0,20}\binto\b)|
(\bdelete\b.{0,20}\bfrom\b)|
(\bdrop\b.{0,20}\btable\b)|
(\bupdate\b.{0,20}\bset\b)|
(\bor\b\s+\d+=\d+)|
(\band\b\s+\d+=\d+)
]]

-- XSS patterns (anti bypass tốt hơn)
local xss_pattern = [[
(<script\b)|
(javascript\s*:)|
(onerror\s*=)|
(onload\s*=)|
(<svg\b)|
(<img\b[^>]*onerror)|
(document\.cookie)|
(alert\s*\()
]]

-- Risk scoring
local SCORE_SQLI      = 40
local SCORE_XSS       = 40
local SCORE_SUSPICIOUS= 15

-- ================= NORMALIZE =================

local function deep_normalize(input)
    if not input then return "" end

    -- decode URL nhiều lần (anti double encoding)
    for _ = 1, 3 do
        input = ngx.unescape_uri(input)
    end

    -- lowercase
    input = string.lower(input)

    -- remove null byte
    input = input:gsub("%z", "")

    -- collapse spaces
    input = input:gsub("%s+", " ")

    return input
end

-- ================= CORE CHECK =================

local function check_value(value, ip)
    local v = deep_normalize(value)

    -- SQLi detection
    if ngx.re.find(v, sqli_pattern, "jo") then
        ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_SQLI
        table.insert(ngx.ctx.flags, "sqli")

        ngx.log(ngx.WARN, "[WAF][SQLi] IP=", ip,
                " score=", ngx.ctx.risk_score,
                " payload=", v)

        return
    end

    -- XSS detection
    if ngx.re.find(v, xss_pattern, "jo") then
        ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_XSS
        table.insert(ngx.ctx.flags, "xss")

        ngx.log(ngx.WARN, "[WAF][XSS] IP=", ip,
                " score=", ngx.ctx.risk_score,
                " payload=", v)

        return
    end

    -- Suspicious encoding / obfuscation
    if ngx.re.find(v, [[(%27|%22|%3c|%3e)]], "jo") then
        ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_SUSPICIOUS
        table.insert(ngx.ctx.flags, "encoded_payload")
    end
end

-- ================= MAIN =================

function _M.run()
    local ip = ngx.ctx.real_ip or ngx.var.remote_addr

    -- init context
    ngx.ctx.risk_score = ngx.ctx.risk_score or 0
    ngx.ctx.flags      = ngx.ctx.flags or {}

    -- ================= 1. URI =================
    local uri = ngx.var.request_uri
    if uri then
        check_value(uri, ip)
    end

    -- ================= 2. QUERY =================
    local args = ngx.req.get_uri_args()

    for _, v in pairs(args) do
        if type(v) == "table" then
            for _, vv in ipairs(v) do
                check_value(vv, ip)
            end
        else
            check_value(v, ip)
        end
    end

    -- ================= 3. BODY =================
    local method = ngx.req.get_method()

    if method == "POST" or method == "PUT" or method == "PATCH" then
        ngx.req.read_body()

        local body = ngx.req.get_body_data()
        if body then
            -- tránh scan body quá lớn (DoS protection)
            if #body < 8192 then
                check_value(body, ip)
            else
                ngx.log(ngx.WARN, "[WAF] Skip large body IP=", ip)
            end
        end
    end

    -- ================= FINAL =================
    -- ❗ không block ở đây → pipeline quyết định
    return nil
end

return _M