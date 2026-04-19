local _M = {}

-- Pattern check URI (GET params, path)
local uri_patterns = {
    [[\bunion\b.{0,20}\bselect\b]],
    [[<script[\s>]]],
    [[javascript\s*:]],
    "\\.\\./"              -- Path traversal: dùng string thường thay vì [[]] vì có ký tự đặc biệt
}

-- Pattern check request body (POST/PUT)
local body_patterns = {
    [[\bunion\b.{0,20}\bselect\b]],
    [[']\s*or\s*[']1[']\s*=\s*[']1]],
    [[;\s*drop\s+table]],
    [[<script[\s>]]],
    [[javascript\s*:]],
}

function _M.run()
    -- 1. Check URI
    local uri = ngx.var.request_uri
    for _, pattern in ipairs(uri_patterns) do
        if ngx.re.find(uri, pattern, "ijo") then
            ngx.log(ngx.WARN, "[WAF] URI pattern blocked: ", uri,
                    " IP: ", ngx.var.remote_addr)
            return ngx.exit(ngx.HTTP_FORBIDDEN)
        end
    end

    -- 2. Check request body chỉ với POST/PUT
    local method = ngx.var.request_method
    if method == "POST" or method == "PUT" then
        ngx.req.read_body()
        local body = ngx.req.get_body_data()

        if body then
            -- flag "i" trong "ijo" đã case-insensitive, không cần string.lower()
            for _, pattern in ipairs(body_patterns) do
                if ngx.re.find(body, pattern, "ijo") then
                    ngx.log(ngx.WARN, "[WAF] Body pattern blocked, IP: ",
                            ngx.var.remote_addr)
                    return ngx.exit(ngx.HTTP_FORBIDDEN)
                end
            end
        end
    end
end

return _M
