local _M = {}

-- ================= CONFIG =================

local MAX_BODY_SIZE   = 8192
local MAX_ARGS_SCAN   = 50

-- 🔥 SQLi (improved anti-bypass)
local sqli_pattern = [[
(\bunion\b\s*(all\s*)?\bselect\b)|
(\bselect\b.+\bfrom\b.+\bwhere\b)|
(\binsert\b\s+into\b)|
(\bdelete\b\s+from\b)|
(\bdrop\b\s+table\b)|
(\bupdate\b.+\bset\b)|
(\bor\b\s+\d+=\d+)|
(\band\b\s+\d+=\d+)|
(--|#|/\*)
]]

-- 🔥 XSS (expanded)
local xss_pattern = [[
(<script\b)|
(<iframe\b)|
(<svg\b)|
(onerror\s*=)|
(onload\s*=)|
(javascript\s*:)|
(data\s*:\s*text/html)|
(document\.cookie)|
(alert\s*\()|
(src\s*=\s*javascript)
]]

-- scoring
local SCORE_SQLI_HIGH = 40
local SCORE_SQLI_LOW  = 20
local SCORE_XSS       = 40
local SCORE_SUSPICIOUS= 10

-- ================= SKIP =================

local function is_safe_path(uri)
    if not uri then return false end

    return uri:find("^/health")
        or uri:find("^/static")
        or uri:find("^/media")
end

-- ================= NORMALIZE =================

local function deep_normalize(input)
    if not input then return "" end

    for _ = 1, 3 do
        input = ngx.unescape_uri(input)
    end

    input = string.lower(input)
    input = input:gsub("%z", "")
    input = input:gsub("%s+", " ")

    return input
end

-- ================= DETECT =================

local function detect_sqli(v)
    if ngx.re.find(v, sqli_pattern, "jo") then
        if ngx.re.find(v, [[union|select|drop|insert|delete]], "jo") then
            return "high"
        end
        return "low"
    end
    return nil
end

local function detect_xss(v)
    return ngx.re.find(v, xss_pattern, "jo")
end

-- ================= CHECK =================

local function check_value(value, ip)
    local v = deep_normalize(value)

    if v == "" then return end

    -- SQLi
    local sqli_level = detect_sqli(v)
    if sqli_level then
        if sqli_level == "high" then
            ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_SQLI_HIGH
        else
            ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_SQLI_LOW
        end

        table.insert(ngx.ctx.flags, "sqli")

        ngx.log(ngx.WARN,
            "[WAF][SQLI] IP=", ip,
            " level=", sqli_level,
            " payload=", v)

        return
    end

    -- XSS
    if detect_xss(v) then
        ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_XSS
        table.insert(ngx.ctx.flags, "xss")

        ngx.log(ngx.WARN,
            "[WAF][XSS] IP=", ip,
            " payload=", v)

        return
    end

    -- encoded suspicious
    if ngx.re.find(v, [[(%27|%22|%3c|%3e)]], "jo") then
        ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_SUSPICIOUS
        table.insert(ngx.ctx.flags, "encoded_payload")
    end
end

-- ================= MAIN =================

function _M.run()
    local ip  = ngx.ctx.real_ip or ngx.var.remote_addr
    local uri = ngx.var.uri

    ngx.ctx.risk_score = ngx.ctx.risk_score or 0
    ngx.ctx.flags      = ngx.ctx.flags or {}

    if is_safe_path(uri) then
        return nil
    end

    -- ================= URI =================
    if uri then
        check_value(uri, ip)
    end

    -- ================= QUERY =================
    local args = ngx.req.get_uri_args()
    local count = 0

    for _, v in pairs(args) do
        count = count + 1
        if count > MAX_ARGS_SCAN then
            ngx.log(ngx.WARN, "[WAF] Too many args, stop scanning IP=", ip)
            break
        end

        if type(v) == "table" then
            for _, vv in ipairs(v) do
                check_value(vv, ip)
            end
        else
            check_value(v, ip)
        end
    end

    -- ================= BODY =================
    local method = ngx.req.get_method()

    if method == "POST" or method == "PUT" or method == "PATCH" then
        ngx.req.read_body()

        local body = ngx.req.get_body_data()

        if body and #body < MAX_BODY_SIZE then
            -- 🔥 tránh false positive JSON
            if not ngx.re.find(body, [[^\s*\{.*\}\s*$]], "jo") then
                check_value(body, ip)
            end
        elseif body then
            ngx.log(ngx.WARN, "[WAF] Body too large skip IP=", ip)
        end
    end

    return nil
end

return _M