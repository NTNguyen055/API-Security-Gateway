local _M = {}

local ngx      = ngx
local re_match = ngx.re.match
local math_min = math.min

-- FIX: require trong function scope, không ở module-level
-- Tránh lỗi khi module được load trước khi lualib sẵn sàng
local function get_libs()
    return
        require "resty.jwt",
        require "resty.sha256",
        require "resty.string"
end

-- FIX: đọc JWT_SECRET trong function, không ở module-level
-- os.getenv ở module-level có thể trả về nil khi load sớm
local function get_secret()
    local s = os.getenv("JWT_SECRET_KEY")
    if not s or s == "" then return nil end
    return s
end

-- Public paths không cần JWT — dễ mở rộng
local PUBLIC_PATHS = {
    ["/login"]    = true,
    ["/login/"]   = true,
    ["/doLogin"]  = true,
    ["/doLogin/"] = true,
    ["/health/"]  = true,
    ["/health"]   = true,
    -- NÂNG CẤP: thêm các path public phổ biến
    ["/doctor/signup/"]  = true,
    ["/doctor/signup"]   = true,
}

-- TTL tối đa cho replay key — tránh cache chiếm quá nhiều bộ nhớ
local MAX_REPLAY_TTL = 3600  -- 1 giờ

-- =============================================================================
-- HASH TOKEN — dùng SHA-256 làm cache key để tránh lưu raw token
-- =============================================================================
local function hash_token(token, sha256_lib, str_lib)
    local sha = sha256_lib:new()
    sha:update(token)
    return str_lib.to_hex(sha:final())
end

-- =============================================================================
-- MAIN
-- =============================================================================
function _M.run(ctx)
    -- FIX: đọc secret mỗi lần gọi (lazy) thay vì ở module-level
    local JWT_SECRET = get_secret()
    if not JWT_SECRET then
        -- Không có secret → bỏ qua JWT check (mode: JWT disabled)
        return
    end

    local uri = ngx.var.uri
    if PUBLIC_PATHS[uri] then
        ctx.security = ctx.security or {}
        ctx.security.jwt_public_path = true
        return
    end

    -- Ưu tiên client_ip từ xff_guard
    local ip = (ctx.security and ctx.security.client_ip)
               or ngx.var.realip_remote_addr
               or ngx.var.remote_addr

    local auth_header = ngx.var.http_authorization

    ctx.security         = ctx.security or {}
    ctx.security.signals = ctx.security.signals or {}

    -- ── MISSING JWT ───────────────────────────────────────────
    if not auth_header then
        ctx.security.jwt_missing = true
        ctx.security.block       = true   -- FIX: missing JWT → block nếu route protected

        local base = 20
        if ctx.security.rate_limit_hard  then base = math_min(base + 10, 100) end
        if ctx.security.waf_sqli or ctx.security.waf_xss then
            base = math_min(base + 15, 100)
        end

        ctx.security.risk = math_min((ctx.security.risk or 0) + base, 100)
        table.insert(ctx.security.signals, "jwt_missing")

        ngx.log(ngx.WARN, "[JWT] Missing ip=", ip, " uri=", uri)
        return
    end

    -- ── FORMAT CHECK ─────────────────────────────────────────
    local m = re_match(
        auth_header,
        [[^Bearer\s+([A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)$]],
        "jo"
    )

    if not m then
        ctx.security.jwt_malformed = true
        ctx.security.block         = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 30, 100)
        table.insert(ctx.security.signals, "jwt_malformed")
        ngx.log(ngx.WARN, "[JWT] Malformed header ip=", ip)
        return
    end

    local token = m[1]

    -- Load libs (lazy, cached by require)
    local jwt_lib, sha256_lib, str_lib = get_libs()
    local token_hash = hash_token(token, sha256_lib, str_lib)

    local cache = ngx.shared.jwt_cache

    -- ── L1 CACHE HIT ─────────────────────────────────────────
    -- FIX: dùng số 1 thay vì boolean
    if cache then
        local cached_val = cache:get(token_hash)
        if cached_val == 1 then
            -- Token đã được verify trước đó và còn hợp lệ
            ctx.security.jwt_valid      = true
            ctx.security.jwt_from_cache = true

            -- Lấy user_id từ cache nếu có
            local uid_key = "jwt_uid:" .. token_hash
            local uid = cache:get(uid_key)
            if uid then
                ngx.req.set_header("X-User-ID", tostring(uid))
            end
            return
        end
        -- cached_val == 2 → previously blocked token
        if cached_val == 2 then
            ctx.security.jwt_invalid = true
            ctx.security.block       = true
            ctx.security.risk        = math_min((ctx.security.risk or 0) + 40, 100)
            table.insert(ctx.security.signals, "jwt_blocked_cache")
            return
        end
    end

    -- ── LOAD JWT STRUCTURE ───────────────────────────────────
    local jwt_obj = jwt_lib:load_jwt(token)

    if not jwt_obj or not jwt_obj.valid then
        ctx.security.jwt_malformed = true
        ctx.security.block         = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 30, 100)
        table.insert(ctx.security.signals, "jwt_malformed")
        -- Cache token xấu để không verify lại (TTL 5 phút)
        if cache then cache:set(token_hash, 2, 300) end
        return
    end

    -- ── ALG CHECK — chống alg:none attack ────────────────────
    if not jwt_obj.header or jwt_obj.header.alg ~= "HS256" then
        ctx.security.jwt_alg_attack = true
        ctx.security.block          = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 80, 100)
        table.insert(ctx.security.signals, "jwt_alg_attack")
        ngx.log(ngx.WARN,
            "[JWT] Alg attack ip=", ip,
            " alg=", tostring(jwt_obj.header and jwt_obj.header.alg)
        )
        if cache then cache:set(token_hash, 2, 300) end
        return
    end

    -- ── VERIFY SIGNATURE ─────────────────────────────────────
    jwt_obj = jwt_lib:verify(JWT_SECRET, token)

    if not jwt_obj or not jwt_obj.verified then
        ctx.security.jwt_invalid = true
        ctx.security.block       = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 50, 100)
        table.insert(ctx.security.signals, "jwt_invalid")
        ngx.log(ngx.WARN,
            "[JWT] Invalid signature ip=", ip,
            " reason=", tostring(jwt_obj and jwt_obj.reason)
        )
        if cache then cache:set(token_hash, 2, 300) end
        return
    end

    -- ── PAYLOAD VALIDATION ───────────────────────────────────
    local payload = jwt_obj.payload
    local now     = ngx.time()

    if not payload or type(payload.user_id) ~= "number" then
        ctx.security.jwt_payload_invalid = true
        ctx.security.block               = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 40, 100)
        table.insert(ctx.security.signals, "jwt_payload_invalid")
        return
    end

    if not payload.exp then
        ctx.security.jwt_no_exp = true
        ctx.security.block      = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 40, 100)
        table.insert(ctx.security.signals, "jwt_no_exp")
        return
    end

    -- ── EXPIRY CHECK ─────────────────────────────────────────
    local ttl = payload.exp - now
    if ttl <= 0 then
        ctx.security.jwt_expired = true
        ctx.security.block       = true
        -- FIX: expired token tăng risk, không phải pass silently
        ctx.security.risk = math_min((ctx.security.risk or 0) + 30, 100)
        table.insert(ctx.security.signals, "jwt_expired")
        ngx.log(ngx.WARN, "[JWT] Expired ip=", ip,
                           " expired_ago=", math.abs(ttl), "s")
        return
    end

    -- ── NBF CHECK ────────────────────────────────────────────
    if payload.nbf and payload.nbf > now then
        ctx.security.jwt_nbf = true
        ctx.security.block   = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 30, 100)
        table.insert(ctx.security.signals, "jwt_nbf")
        return
    end

    -- ── REPLAY DETECTION ─────────────────────────────────────
    -- FIX: không require risk > 30 nữa — detect replay bất kể risk hiện tại
    local replay_key = "jwt_ip:" .. token_hash
    if cache then
        local prev_ip = cache:get(replay_key)
        if prev_ip and prev_ip ~= ip then
            -- Token đang được dùng từ IP khác → flag replay
            ctx.security.jwt_replay = true
            ctx.security.risk = math_min((ctx.security.risk or 0) + 30, 100)
            table.insert(ctx.security.signals, "jwt_replay")
            ngx.log(ngx.WARN,
                "[JWT] Replay detected ip=", ip,
                " prev_ip=", prev_ip,
                " user_id=", payload.user_id
            )
        else
            -- FIX: cap TTL replay key để tránh cache bị chiếm lâu
            cache:set(replay_key, ip, math.min(ttl, MAX_REPLAY_TTL))
        end
    end

    -- ── CACHE VALID TOKEN ────────────────────────────────────
    -- FIX: dùng số 1 thay vì boolean
    if cache then
        local cache_ttl = math.min(ttl, MAX_REPLAY_TTL)
        cache:set(token_hash, 1, cache_ttl)
        -- Cache user_id riêng để dùng khi cache hit
        cache:set("jwt_uid:" .. token_hash, payload.user_id, cache_ttl)
    end

    -- ── FORWARD IDENTITY HEADERS ─────────────────────────────
    ngx.req.set_header("X-User-ID",   tostring(payload.user_id))
    ngx.req.set_header("X-User-Role", tostring(payload.role or "user"))

    ctx.identity = {
        user_id = payload.user_id,
        role    = payload.role or "user",
    }

    ctx.security.jwt_valid = true
end

return _M
