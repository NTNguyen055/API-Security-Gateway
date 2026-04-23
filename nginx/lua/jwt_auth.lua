local _M = {}

local jwt = require "resty.jwt"
local sha256 = require "resty.sha256"
local str = require "resty.string"

local JWT_SECRET = os.getenv("JWT_SECRET_KEY")

if not JWT_SECRET or JWT_SECRET == "" then
    ngx.log(ngx.ERR, "[JWT] Missing JWT_SECRET_KEY → skip")
end

local function hash_token(token)
    local sha = sha256:new()
    sha:update(token)
    return str.to_hex(sha:final())
end

function _M.run()
    if not JWT_SECRET then
        return nil
    end

    local uri = ngx.var.uri

    if not ngx.re.find(uri, "^/api/", "jo") then
        return nil
    end

    local ip = ngx.var.remote_addr

    local auth_header = ngx.var.http_authorization
    if not auth_header then
        ngx.log(ngx.WARN, "[JWT] Missing Authorization IP: ", ip)
        if metric_blocked then metric_blocked:inc(1, {"jwt_missing"}) end
        return 401
    end

    local m = ngx.re.match(auth_header, [[^Bearer\s+([A-Za-z0-9\-\._]+)$]], "jo")
    if not m then
        return 401
    end

    local token = m[1]
    local token_hash = hash_token(token)

    -- L1: cache
    local cache = ngx.shared.jwt_cache
    if cache:get(token_hash) then
        return nil
    end

    local jwt_obj = jwt:verify(JWT_SECRET, token)

    if not jwt_obj.verified then
        ngx.log(ngx.WARN, "[JWT] Invalid token: ", jwt_obj.reason, " IP: ", ip)
        if metric_blocked then metric_blocked:inc(1, {"jwt_invalid"}) end
        return 401
    end

    -- 🔥 check alg
    if jwt_obj.header.alg ~= "HS256" then
        return 401
    end

    local payload = jwt_obj.payload

    if not payload or type(payload.user_id) ~= "number" then
        return 401
    end

    -- 🔥 exp check chuẩn
    if not payload.exp or payload.exp < ngx.time() then
        return 401
    end

    -- 🔥 optional issuer check
    -- if payload.iss ~= "docapp" then return 401 end

    local ttl = payload.exp - ngx.time()
    if ttl > 0 then
        cache:set(token_hash, true, ttl)
    end

    ngx.req.set_header("X-User-ID",   tostring(payload.user_id))
    ngx.req.set_header("X-User-Role", tostring(payload.role or "user"))

    return nil
end

return _M