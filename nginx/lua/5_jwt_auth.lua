local _M = {}

local jwt = require "resty.jwt"

-- Đọc từ env 1 lần ở module level — không hardcode, không dùng global undefined
-- Biến này phải là JWT_SECRET_KEY trong .env (khác với SECRET_KEY của Django)
local JWT_SECRET = os.getenv("JWT_SECRET_KEY")

if not JWT_SECRET or JWT_SECRET == "" then
    ngx.log(ngx.ERR, "[JWT] JWT_SECRET_KEY chưa được set trong .env — module sẽ skip")
end

-- Whitelist: path KHÔNG cần JWT
-- Khớp với urls.py: login, doLogin, docsignup, index (/), health
local public_paths = {
    "^/health",
    "^/login",
    "^/doLogin",
    "^/doLogout",
    "^/docsignup",
    "^/static/",
    "^/media/",
    "^/$",                  -- trang index
    "^/Website/",
    "^/base/",
    "^/userbase/",
}

function _M.run()
    -- Skip nếu secret chưa set (fail-open với log)
    if not JWT_SECRET then
        return
    end

    local uri = ngx.var.request_uri

    -- Chỉ enforce JWT trên /api/* routes
    -- Hệ thống hiện tại dùng session-based auth (Django), không có /api/ prefix
    -- → module này sẽ skip toàn bộ cho đến khi có API endpoint thực sự
    if not ngx.re.find(uri, [[^/api/]], "jo") then
        return
    end

    -- Kiểm tra whitelist
    for _, pattern in ipairs(public_paths) do
        if ngx.re.find(uri, pattern, "jo") then
            return
        end
    end

    -- Lấy token từ Authorization header
    -- Nginx lowercase tất cả header → dùng http_authorization (không phải http_Authorization)
    local auth_header = ngx.var.http_authorization
    if not auth_header then
        ngx.log(ngx.WARN, "[JWT] Missing Authorization, URI: ", uri,
                " IP: ", ngx.var.remote_addr)
        return ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end

    local token = string.match(auth_header, "[Bb]earer%s+(.+)")
    if not token then
        return ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end

    -- Verify chữ ký + exp (lua-resty-jwt tự check exp)
    local jwt_obj = jwt:verify(JWT_SECRET, token)

    if not jwt_obj.verified then
        ngx.log(ngx.WARN, "[JWT] Invalid token: ", jwt_obj.reason,
                " IP: ", ngx.var.remote_addr)
        return ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end

    -- Double-check exp tường minh
    local payload = jwt_obj.payload
    if not payload or not payload.exp or payload.exp < ngx.now() then
        ngx.log(ngx.WARN, "[JWT] Token expired, IP: ", ngx.var.remote_addr)
        return ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end

    -- Forward thông tin user cho Django qua header
    ngx.req.set_header("X-User-ID",   tostring(payload.user_id or ""))
    ngx.req.set_header("X-User-Role", tostring(payload.role    or ""))
end

return _M
