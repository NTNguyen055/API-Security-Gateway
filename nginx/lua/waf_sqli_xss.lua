local _M = {}

-- SQLi patterns (SAFE VERSION - giảm false positive)
local sqli_pattern = [[
(\bunion\s+select\b)|
(\bselect\b.+\bfrom\b.+\bwhere\b)|
(\binsert\s+into\b)|
(\bdelete\s+from\b)|
(\bdrop\s+table\b)|
(\bupdate\b.+\bset\b)
]]

-- XSS patterns (giữ nguyên nhưng tối ưu nhẹ)
local xss_pattern = [[
(<script\b)|
(javascript\s*:)|
(onerror\s*=)|
(onload\s*=)|
(<svg\b)|
(<img\b.*onerror)
]]

local function normalize(input)
    if not input then return "" end
    input = ngx.unescape_uri(input)
    return string.lower(input)
end

local function check(value, ip)
    local v = normalize(value)

    -- SQLi check
    if ngx.re.find(v, sqli_pattern, "jo") then
        ngx.log(ngx.WARN, "[WAF][SQLi] Blocked IP: ", ip)
        if metric_blocked then metric_blocked:inc(1, {"waf_sqli"}) end
        return 403
    end

    -- XSS check
    if ngx.re.find(v, xss_pattern, "jo") then
        ngx.log(ngx.WARN, "[WAF][XSS] Blocked IP: ", ip)
        if metric_blocked then metric_blocked:inc(1, {"waf_xss"}) end
        return 403
    end

    return nil
end

function _M.run()
    local ip = ngx.var.remote_addr

    -- 1. URI
    local uri = ngx.var.request_uri
    local code = check(uri, ip)
    if code then return code end

    -- 2. Query args
    local args = ngx.req.get_uri_args()
    for _, v in pairs(args) do
        if type(v) == "table" then
            for _, vv in ipairs(v) do
                local code = check(vv, ip)
                if code then return code end
            end
        else
            local code = check(v, ip)
            if code then return code end
        end
    end

    -- 3. Body
    local method = ngx.req.get_method()
    if method == "POST" or method == "PUT" then
        ngx.req.read_body()

        local body = ngx.req.get_body_data()
        if body then
            local code = check(body, ip)
            if code then return code end
        end
    end

    return nil
end

return _M