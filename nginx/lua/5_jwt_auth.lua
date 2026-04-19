local _M = {}

local jwt = require "resty.jwt"

local JWT_SECRET = os.getenv("JWT_SECRET_KEY")

if not JWT_SECRET or JWT_SECRET == "" then
    ngx.log(ngx.ERR, "[JWT] Missing JWT_SECRET_KEY → skip")
end

function _M.run()
    if not JWT_SECRET then
        return
    end

    local uri = ngx.var.uri

    -- 🔥 Chỉ protect API
    if not ngx.re.find(uri, "^/api/", "jo") then
        return
    end

    local ip = ngx.var.remote_addr

    local auth_header = ngx.var.http_authorization
    if not auth_header then
        ngx.log(ngx.WARN, "[JWT] Missing Authorization IP: ", ip)
        return ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end

    -- Strict Bearer format
    local m = ngx.re.match(auth_header, [[^Bearer\s+(.+)$]], "jo")
    if not m then
        return ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end

    local token = m[1]

    -- =========================
    -- JWT CACHE (RAM)
    -- =========================
    local cache = ngx.shared.jwt_cache
    local cached = cache:get(token)

    if cached then
        return
    end

    local jwt_obj = jwt:verify(JWT_SECRET, token)

    if not jwt_obj.verified then
        ngx.log(ngx.WARN, "[JWT] Invalid token: ", jwt_obj.reason, " IP: ", ip)
        return ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end

    local payload = jwt_obj.payload

    -- validate payload structure
    if not payload or type(payload.user_id) ~= "number" then
        return ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end

    if not payload.exp or payload.exp < ngx.now() then
        return ngx.exit(ngx.HTTP_UNAUTHORIZED)
    end

    -- cache token (TTL theo exp)
    local ttl = payload.exp - ngx.now()
    if ttl > 0 then
        cache:set(token, true, ttl)
    end

    -- forward identity
    ngx.req.set_header("X-User-ID", tostring(payload.user_id))
    ngx.req.set_header("X-User-Role", tostring(payload.role or "user"))
end

return _M