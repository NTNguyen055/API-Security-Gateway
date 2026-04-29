local _M = {}

local jwt = require "resty.jwt"
local sha256 = require "resty.sha256"
local str = require "resty.string"

local ngx = ngx
local re_match = ngx.re.match
local math_min = math.min

-- [FIX] Đã xóa JWT_SECRET ở đây để chuyển vào bên trong hàm run

local PUBLIC_PATHS = {
    ["/login"] = true,
    ["/login/"] = true,
    ["/doLogin"] = true,
    ["/doLogin/"] = true,
    ["/health"] = true,
    ["/health/"] = true,
    ["/doctor/signup/"] = true,    -- [MỚI] Cho phép bác sĩ đăng ký
    ["/admin/login/"] = true       -- [MỚI] Cho phép đăng nhập Django Admin
}

local function hash_token(token)
    local sha = sha256:new()
    sha:update(token)
    return str.to_hex(sha:final())
end

function _M.run(ctx)
    -- [FIX] Đọc JWT_SECRET động bên trong hàm để luôn bắt được key mới nhất
    local JWT_SECRET = os.getenv("JWT_SECRET_KEY")
    if not JWT_SECRET or JWT_SECRET == "" then
        return
    end

    local uri = ngx.var.uri
    if PUBLIC_PATHS[uri] then
        return
    end

    local ip = ngx.var.realip_remote_addr or ngx.var.remote_addr
    local auth_header = ngx.var.http_authorization

    ctx.security = ctx.security or {}
    ctx.security.signals = ctx.security.signals or {}

    if not auth_header then
        ctx.security.jwt_missing = true

        local base = 10
        if ctx.security.rate_limit_hard then base = base + 10 end
        if ctx.security.waf_sqli or ctx.security.waf_xss then base = base + 15 end

        ctx.security.risk = math_min((ctx.security.risk or 0) + base, 100)

        table.insert(ctx.security.signals, "jwt_missing")

        ngx.log(ngx.WARN, "[JWT] Missing IP=", ip)
        return
    end

    local m = re_match(auth_header,
        [[^Bearer\s+([A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)$]],
        "jo"
    )

    if not m then
        ctx.security.jwt_malformed = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 20, 100)
        table.insert(ctx.security.signals, "jwt_malformed")
        return
    end

    local token = m[1]
    local token_hash = hash_token(token)

    local cache = ngx.shared.jwt_cache

    -- [FIX] Khôi phục Session từ Cache thay vì chỉ bypass
    if cache then
        local cached_payload = cache:get(token_hash)
        if cached_payload then
            -- Tách user_id và role từ chuỗi cache
            local user_id, role = cached_payload:match("^([^:]+):(.*)$")
            if user_id then
                ngx.req.set_header("X-User-ID", user_id)
                ngx.req.set_header("X-User-Role", role or "user")

                ctx.identity = {
                    user_id = tonumber(user_id) or user_id,
                    role = role or "user"
                }
                ctx.security.jwt_valid = true
                return
            end
        end
    end

    -- LOAD JWT FIRST
    local jwt_obj = jwt:load_jwt(token)

    if not jwt_obj.valid then
        ctx.security.jwt_malformed = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 20, 100)
        table.insert(ctx.security.signals, "jwt_malformed")
        return
    end

    -- ALG CHECK FIRST
    if jwt_obj.header.alg ~= "HS256" then
        ctx.security.jwt_alg_attack = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 50, 100)
        table.insert(ctx.security.signals, "jwt_alg_attack")
        return
    end

    jwt_obj = jwt:verify(JWT_SECRET, token)

    if not jwt_obj.verified then
        ctx.security.jwt_invalid = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 40, 100)
        table.insert(ctx.security.signals, "jwt_invalid")
        return
    end

    local payload = jwt_obj.payload
    local now = ngx.time()

    if not payload or type(payload.user_id) ~= "number" then
        ctx.security.jwt_payload_invalid = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 30, 100)
        table.insert(ctx.security.signals, "jwt_payload_invalid")
        return
    end

    if not payload.exp then
        ctx.security.jwt_no_exp = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 30, 100)
        table.insert(ctx.security.signals, "jwt_no_exp")
        return
    end

    local ttl = payload.exp - now
    if ttl <= 0 then
        ctx.security.jwt_expired = true
        table.insert(ctx.security.signals, "jwt_expired")
        return
    end

    if payload.nbf and payload.nbf > now then
        ctx.security.jwt_nbf = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 20, 100)
        table.insert(ctx.security.signals, "jwt_nbf")
        return
    end

    local replay_key = "jwt_ip:" .. token_hash
    local prev_ip = cache and cache:get(replay_key)

    if prev_ip and prev_ip ~= ip and (ctx.security.risk or 0) > 30 then
        ctx.security.jwt_replay = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 10, 100)
        table.insert(ctx.security.signals, "jwt_replay")
    else
        if cache then
            cache:set(replay_key, ip, ttl)
        end
    end

    if cache then
        -- [FIX] Lưu định dạng "user_id:role" vào cache để tái sử dụng
        local cache_val = tostring(payload.user_id) .. ":" .. tostring(payload.role or "user")
        cache:set(token_hash, cache_val, ttl)
    end

    ngx.req.set_header("X-User-ID", tostring(payload.user_id))
    ngx.req.set_header("X-User-Role", tostring(payload.role or "user"))

    ctx.identity = {
        user_id = payload.user_id,
        role = payload.role or "user"
    }

    ctx.security.jwt_valid = true
end

return _M