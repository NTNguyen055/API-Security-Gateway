local _M = {}

local uri_patterns = {
    [[\bunion\b.{0,20}\bselect\b]],
    "<script[\\s>]",
    "javascript\\s*:",
    "\\.\\./"
}

local body_patterns = {
    [[\bunion\b.{0,20}\bselect\b]],
    "'\\s*or\\s*'1'\\s*=\\s*'1'",
    ";\\s*drop\\s+table",
    "<script[\\s>]",
    "javascript\\s*:"
}

function _M.run()
    local uri = ngx.var.request_uri

    for _, pattern in ipairs(uri_patterns) do
        if ngx.re.find(uri, pattern, "ijo") then
            ngx.log(ngx.WARN, "[WAF] URI blocked: ", uri, " IP: ", ngx.var.remote_addr)
            if metric_blocked then metric_blocked:inc(1, {"waf"}) end
            return 403
        end
    end

    local method = ngx.var.request_method
    if method == "POST" or method == "PUT" then
        ngx.req.read_body()
        local body = ngx.req.get_body_data()
        if body then
            for _, pattern in ipairs(body_patterns) do
                if ngx.re.find(body, pattern, "ijo") then
                    ngx.log(ngx.WARN, "[WAF] Body blocked IP: ", ngx.var.remote_addr)
                    if metric_blocked then metric_blocked:inc(1, {"waf"}) end
                    return 403
                end
            end
        end
    end

    return nil  -- cho qua
end

return _M
