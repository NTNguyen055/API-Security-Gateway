local _M = {}

-- ================= DEPENDENCIES =================
local jwt    = require "resty.jwt"
local sha256 = require "resty.sha256"
local str    = require "resty.string"
local redis  = require "resty.redis"

-- ================= CONFIG =================

local JWT_SECRET = os.getenv("JWT_SECRET_KEY")

local REDIS_DOWN_TTL = 5
local CACHE_PREFIX   = "jwt:"
local REVOKE_PREFIX  = "jwt_bl:"
local REPLAY_PREFIX  = "jwt_rp:"

-- Risk scoring
local SCORE_MISSING   = 20
local SCORE_INVALID   = 40
local SCORE_REPLAY    = 50

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

    local ok, err = red:connect("redis", 6379)
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

    -- chỉ protect API
    if not ngx.re.find(uri, "^/api/", "jo") then
        return nil
    end

    local ip = ngx.ctx.real_ip or ngx.var.remote_addr

    -- init scoring
    ngx.ctx.risk_score = ngx.ctx.risk_score or 0
    ngx.ctx.flags      = ngx.ctx.flags or {}

    -- ================= AUTH HEADER =================
    local auth_header = ngx.var.http_authorization
    if not auth_header then
        ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_MISSING
        table.insert(ngx.ctx.flags, "jwt_missing")

        ngx.log(ngx.WARN, "[JWT] Missing token IP=", ip)
        return nil
    end

    local m = ngx.re.match(auth_header,
        [[^Bearer\s+([A-Za-z0-9\-\._~\+\/]+=*)$]], "jo")

    if not m then
        ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_INVALID
        table.insert(ngx.ctx.flags, "jwt_malformed")
        return nil
    end

    local token = m[1]
    local token_hash = hash_token(token)

    -- ================= L1 CACHE =================
    local cache = ngx.shared.jwt_cache
    if cache and cache:get(CACHE_PREFIX .. token_hash) then
        return nil
    end

    -- ================= REDIS =================
    local red, err = get_redis()

    -- ================= REVOKE CHECK =================
    if red then
        local revoked = red:get(REVOKE_PREFIX .. token_hash)
        if revoked and revoked ~= ngx.null then
            ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_INVALID
            table.insert(ngx.ctx.flags, "jwt_revoked")

            ngx.log(ngx.WARN, "[JWT] Revoked token IP=", ip)
            red:set_keepalive(10000, 100)
            return nil
        end
    end

    -- ================= VERIFY =================
    local jwt_obj = jwt:verify(JWT_SECRET, token)

    if not jwt_obj.verified then
        ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_INVALID
        table.insert(ngx.ctx.flags, "jwt_invalid")

        ngx.log(ngx.WARN, "[JWT] Invalid token IP=", ip,
                " reason=", jwt_obj.reason)
        return nil
    end

    -- ================= PAYLOAD =================
    local payload = jwt_obj.payload

    if not payload or type(payload.user_id) ~= "number" then
        ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_INVALID
        table.insert(ngx.ctx.flags, "jwt_bad_payload")
        return nil
    end

    -- exp check
    if not payload.exp or payload.exp < ngx.time() then
        ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_INVALID
        table.insert(ngx.ctx.flags, "jwt_expired")
        return nil
    end

    -- ================= ANTI-REPLAY =================
    if red and payload.jti then
        local replay_key = REPLAY_PREFIX .. payload.jti

        local ok, _ = red:set(replay_key, 1, "NX", "EX", 60)

        if not ok then
            ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_REPLAY
            table.insert(ngx.ctx.flags, "jwt_replay")

            ngx.log(ngx.WARN, "[JWT] Replay detected IP=", ip)
            red:set_keepalive(10000, 100)
            return nil
        end
    end

    -- ================= CACHE =================
    local ttl = payload.exp - ngx.time()
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