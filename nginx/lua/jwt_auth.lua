local _M = {}

-- ============================================================
-- JWT AUTH — FINAL (SECURE + OPTIMIZED)
-- ============================================================

local jwt = require "resty.jwt"
local sha256 = require "resty.sha256"
local str = require "resty.string"

local ngx = ngx
local re_match = ngx.re.match
local math_min = math.min

local JWT_SECRET = os.getenv("JWT_SECRET_KEY")

-- ============================================================
-- PUBLIC ENDPOINTS (FIXED)
-- ============================================================

local PUBLIC_PATHS = {
    ["/login/"]   = true,
    ["/doLogin/"] = true,
    ["/health/"]  = true
}

-- ============================================================
-- HASH TOKEN
-- ============================================================

local function hash_token(token)
    local sha = sha256:new()
    sha:update(token)
    return str.to_hex(sha:final())
end

-- ============================================================
-- MAIN
-- ============================================================

function _M.run(ctx)
    if not JWT_SECRET or JWT_SECRET == "" then
        return
    end

    local uri = ngx.var.uri

    -- ========================================================
    -- SKIP PUBLIC PATH
    -- ========================================================
    if PUBLIC_PATHS[uri] then
        return
    end

    local ip = ngx.var.remote_addr
    local auth_header = ngx.var.http_authorization

    ctx.security = ctx.security or {}

    -- ========================================================
    -- MISSING TOKEN
    -- ========================================================
    if not auth_header then
        ctx.security.jwt_missing = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 10, 100)

        ngx.log(ngx.WARN, "[JWT] Missing IP=", ip)
        return
    end

    -- ========================================================
    -- STRICT FORMAT CHECK
    -- ========================================================
    local m = re_match(auth_header,
        [[^Bearer\s+([A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)$]],
        "jo"
    )

    if not m then
        ctx.security.jwt_malformed = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 20, 100)
        return
    end

    local token = m[1]
    local token_hash = hash_token(token)

    local cache = ngx.shared.jwt_cache

    -- ========================================================
    -- CACHE HIT (VALID TOKEN)
    -- ========================================================
    if cache and cache:get(token_hash) then
        return
    end

    -- ========================================================
    -- VERIFY SIGNATURE
    -- ========================================================
    local jwt_obj = jwt:verify(JWT_SECRET, token)

    if not jwt_obj.verified then
        ctx.security.jwt_invalid = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 40, 100)

        ngx.log(ngx.WARN,
            "[JWT] Invalid IP=", ip,
            " reason=", jwt_obj.reason
        )
        return
    end

    -- ========================================================
    -- ALG CHECK
    -- ========================================================
    if jwt_obj.header.alg ~= "HS256" then
        ctx.security.jwt_alg_attack = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 50, 100)
        return
    end

    local payload = jwt_obj.payload
    local now = ngx.time()

    -- ========================================================
    -- PAYLOAD VALIDATION
    -- ========================================================
    if not payload or type(payload.user_id) ~= "number" then
        ctx.security.jwt_payload_invalid = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 30, 100)
        return
    end

    -- ========================================================
    -- EXP CHECK
    -- ========================================================
    if not payload.exp then
        ctx.security.jwt_no_exp = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 30, 100)
        return
    end

    if payload.exp < now then
        ctx.security.jwt_expired = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 15, 100)
        return
    end

    -- ========================================================
    -- NBF CHECK (NEW - FIX)
    -- ========================================================
    if payload.nbf and payload.nbf > now then
        ctx.security.jwt_nbf = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 20, 100)

        ngx.log(ngx.WARN, "[JWT] Not yet valid IP=", ip)
        return
    end

    -- ========================================================
    -- REPLAY DETECTION (REDUCED RISK)
    -- ========================================================
    local replay_key = "jwt_ip:" .. token_hash
    local prev_ip = cache and cache:get(replay_key)

    if prev_ip and prev_ip ~= ip then
        ctx.security.jwt_replay = true

        -- 🔥 giảm risk để tránh false positive
        ctx.security.risk = math_min((ctx.security.risk or 0) + 10, 100)

        ngx.log(ngx.WARN,
            "[JWT] Replay old=", prev_ip,
            " new=", ip
        )
    else
        if cache then
            cache:set(replay_key, ip, payload.exp - now)
        end
    end

    -- ========================================================
    -- CACHE VALID TOKEN
    -- ========================================================
    local ttl = payload.exp - now

    if cache and ttl > 0 then
        cache:set(token_hash, true, ttl)
    end

    -- ========================================================
    -- PASS USER CONTEXT
    -- ========================================================
    ngx.req.set_header("X-User-ID",   tostring(payload.user_id))
    ngx.req.set_header("X-User-Role", tostring(payload.role or "user"))

    ctx.security.jwt_valid = true
end

return _M