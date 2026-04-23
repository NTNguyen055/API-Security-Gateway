local _M = {}

local jwt = require "resty.jwt"

local JWT_SECRET = os.getenv("JWT_SECRET_KEY")

if not JWT_SECRET or JWT_SECRET == "" then
    ngx.log(ngx.ERR, "[JWT] Missing JWT_SECRET_KEY → skip")
end

function _M.run()
    if not JWT_SECRET then
        return nil  -- skip, fail-open
    end

    local uri = ngx.var.uri

    -- Chỉ protect /api/*
    if not ngx.re.find(uri, "^/api/", "jo") then
        return nil
    end

    local ip = ngx.var.remote_addr

    local auth_header = ngx.var.http_authorization
    if not auth_header then
        ngx.log(ngx.WARN, "[JWT] Missing Authorization IP: ", ip)
        return 401
    end

    local m = ngx.re.match(auth_header, [[^Bearer\s+(.+)$]], "jo")
    if not m then
        return 401
    end

    local token = m[1]

    -- L1: JWT cache
    local cache = ngx.shared.jwt_cache
    if cache:get(token) then
        return nil  -- token đã verified, cho qua
    end

    local jwt_obj = jwt:verify(JWT_SECRET, token)

    if not jwt_obj.verified then
        ngx.log(ngx.WARN, "[JWT] Invalid token: ", jwt_obj.reason, " IP: ", ip)
        return 401
    end

    local payload = jwt_obj.payload

    if not payload or type(payload.user_id) ~= "number" then
        return 401
    end

    if not payload.exp or payload.exp < ngx.now() then
        return 401
    end

    -- Cache token theo TTL
    local ttl = payload.exp - ngx.now()
    if ttl > 0 then
        cache:set(token, true, ttl)
    end

    ngx.req.set_header("X-User-ID",   tostring(payload.user_id))
    ngx.req.set_header("X-User-Role", tostring(payload.role or "user"))

    return nil  -- cho qua
end

return _M
