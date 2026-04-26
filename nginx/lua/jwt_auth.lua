local _M = {}

-- ================= DEPENDENCIES =================
local jwt    = require "resty.jwt"
local sha256 = require "resty.sha256"
local str    = require "resty.string"
local redis  = require "resty.redis"

-- ================= CONFIG =================

local JWT_SECRET = os.getenv("JWT_SECRET_KEY")

local REDIS_HOST = "redis"
local REDIS_PORT = 6379

local REDIS_DOWN_TTL = 5

local CACHE_PREFIX   = "jwt:v2:"
local REVOKE_PREFIX  = "jwt_bl:v1:"
local REPLAY_PREFIX  = "jwt_rp:v2:"

local EXPECTED_ISS = "docapp"
local EXPECTED_AUD = "docapp-users"

local MAX_TOKEN_SIZE = 2048

-- Risk scoring
local SCORE_MISSING = 20
local SCORE_INVALID = 40
local SCORE_REPLAY  = 50
local SCORE_BRUTE   = 15

-- ================= SKIP =================

local function is_public_path(uri)
    if not uri then return false end

    return uri:find("^/health")
        or uri:find("^/login")
        or uri:find("^/static")
        or uri:find("^/media")
end

-- ================= UTIL =================

local function hash_token(token)
    local sha = sha256:new()
    sha:update(token)
    return str.to_hex(sha:final())
end

local function get_redis()
    local cb = ngx.shared.redis_down
    if cb and cb:get("down") then
        return nil, "circuit_open"
    end

    local red = redis:new()
    red:set_timeouts(100, 100, 100)

    local ok, err = red:connect(REDIS_HOST, REDIS_PORT)
    if not ok then
        if cb then cb:set("down", true, REDIS_DOWN_TTL) end
        return nil, err
    end

    return red, nil
end

-- ================= CORE =================

function _M.run()
    if not JWT_SECRET then
        return nil
    end

    local uri = ngx.var.uri
    local ip  = ngx.ctx.real_ip or ngx.var.remote_addr

    ngx.ctx.risk_score = ngx.ctx.risk_score or 0
    ngx.ctx.flags      = ngx.ctx.flags or {}

    if is_public_path(uri) then
        return nil
    end

    -- ================= AUTH HEADER =================
    local auth_header = ngx.var.http_authorization
    if not auth_header then
        ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_MISSING
        table.insert(ngx.ctx.flags, "jwt_missing")
        return nil
    end

    local m = ngx.re.match(auth_header,
        [[^Bearer\s+(.+)$]], "jo")

    if not m then
        ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_INVALID
        table.insert(ngx.ctx.flags, "jwt_malformed")
        return nil
    end

    local token = m[1]

    -- 🔥 limit size
    if #token > MAX_TOKEN_SIZE then
        ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_INVALID
        table.insert(ngx.ctx.flags, "jwt_oversize")
        return nil
    end

    local token_hash = hash_token(token)

    -- ================= CACHE =================
    local cache = ngx.shared.jwt_cache
    if cache and cache:get(CACHE_PREFIX .. token_hash) then
        return nil
    end

    -- ================= REDIS =================
    local red, err = get_redis()

    if not red then
        ngx.ctx.risk_score = ngx.ctx.risk_score + 5
        table.insert(ngx.ctx.flags, "redis_down")
    end

    -- ================= REVOKE =================
    if red then
        local revoked = red:get(REVOKE_PREFIX .. token_hash)
        if revoked and revoked ~= ngx.null then
            ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_INVALID
            table.insert(ngx.ctx.flags, "jwt_revoked")
            red:set_keepalive(10000, 100)
            return nil
        end
    end

    -- ================= VERIFY =================
    local jwt_obj = jwt:load_jwt(token)

    if not jwt_obj.valid then
        ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_INVALID
        table.insert(ngx.ctx.flags, "jwt_invalid")
        return nil
    end

    -- 🔥 strict alg check
    if jwt_obj.header.alg ~= "HS256" then
        ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_INVALID
        table.insert(ngx.ctx.flags, "jwt_alg_invalid")
        return nil
    end

    jwt_obj = jwt:verify(JWT_SECRET, token, { alg = "HS256" })

    if not jwt_obj.verified then
        ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_INVALID
        table.insert(ngx.ctx.flags, "jwt_invalid")
        return nil
    end

    local payload = jwt_obj.payload

    -- ================= CLAIM =================
    if payload.iss ~= EXPECTED_ISS or payload.aud ~= EXPECTED_AUD then
        ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_INVALID
        table.insert(ngx.ctx.flags, "jwt_claims_invalid")
        return nil
    end

    if not payload.user_id or type(payload.user_id) ~= "number" then
        ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_INVALID
        table.insert(ngx.ctx.flags, "jwt_bad_payload")
        return nil
    end

    local now = ngx.time()

    if payload.nbf and payload.nbf > now then
        ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_INVALID
        table.insert(ngx.ctx.flags, "jwt_not_yet_valid")
        return nil
    end

    if not payload.exp or payload.exp < now then
        ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_INVALID
        table.insert(ngx.ctx.flags, "jwt_expired")
        return nil
    end

    -- ================= REPLAY =================
    if red and payload.jti then
        local ttl = payload.exp - now

        if ttl > 0 then
            local key = REPLAY_PREFIX .. payload.jti .. ":" .. ip

            local res = red:set(key, 1, "NX", "EX", ttl)

            if res == ngx.null then
                ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_REPLAY
                table.insert(ngx.ctx.flags, "jwt_replay")
                red:set_keepalive(10000, 100)
                return nil
            end
        end
    end

    -- ================= CACHE =================
    local ttl = payload.exp - now
    if ttl > 0 and cache then
        cache:set(CACHE_PREFIX .. token_hash, true, ttl)
    end

    if red then
        red:set_keepalive(10000, 100)
    end

    -- ================= CONTEXT =================
    ngx.req.set_header("X-User-ID",   tostring(payload.user_id))
    ngx.req.set_header("X-User-Role", tostring(payload.role or "user"))

    return nil
end

return _M