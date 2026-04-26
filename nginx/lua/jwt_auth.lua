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

local CACHE_PREFIX   = "jwt:v1:"
local REVOKE_PREFIX  = "jwt_bl:v1:"
local REPLAY_PREFIX  = "jwt_rp:v1:"

local EXPECTED_ISS = "docapp"
local EXPECTED_AUD = "docapp-users"

-- Risk scoring
local SCORE_MISSING = 20
local SCORE_INVALID = 40
local SCORE_REPLAY  = 50

-- log rate limit
local LOG_TTL = 10

-- ================= UTIL =================

local function hash_token(token)
    local sha = sha256:new()
    sha:update(token)
    return str.to_hex(sha:final())
end

local function log_once(key, msg)
    local dict = ngx.shared.limit_req_store
    if not dict then return end

    local ok = dict:add(key, true, LOG_TTL)
    if ok then
        ngx.log(ngx.WARN, msg)
    end
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

    if not ngx.re.find(ngx.var.uri, "^/api/", "jo") then
        return nil
    end

    local ip = ngx.ctx.real_ip or ngx.var.remote_addr

    ngx.ctx.risk_score = ngx.ctx.risk_score or 0
    ngx.ctx.flags      = ngx.ctx.flags or {}

    -- ================= AUTH HEADER =================
    local auth_header = ngx.var.http_authorization
    if not auth_header then
        ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_MISSING
        table.insert(ngx.ctx.flags, "jwt_missing")
        return nil
    end

    local m = ngx.re.match(auth_header,
        [[^Bearer\s+([A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+)$]], "jo")

    if not m then
        ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_INVALID
        table.insert(ngx.ctx.flags, "jwt_malformed")
        return nil
    end

    local token = m[1]
    local token_hash = hash_token(token)

    -- ================= CACHE =================
    local cache = ngx.shared.jwt_cache
    if cache and cache:get(CACHE_PREFIX .. token_hash) then
        return nil
    end

    -- ================= REDIS =================
    local red, err = get_redis()
    if not red then
        log_once("redis_down", "[JWT] Redis unavailable: " .. (err or ""))
    end

    -- ================= REVOKE =================
    if red then
        local revoked = red:get(REVOKE_PREFIX .. token_hash)
        if revoked and revoked ~= ngx.null then
            ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_INVALID
            table.insert(ngx.ctx.flags, "jwt_revoked")

            log_once("jwt_rev:" .. ip, "[JWT] Revoked token IP=" .. ip)

            red:set_keepalive(10000, 100)
            return nil
        end
    end

    -- ================= VERIFY =================
    local jwt_obj = jwt:verify(JWT_SECRET, token, {
        alg = "HS256"
    })

    if not jwt_obj.verified then
        ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_INVALID
        table.insert(ngx.ctx.flags, "jwt_invalid")

        log_once("jwt_inv:" .. ip, "[JWT] Invalid token IP=" .. ip)
        return nil
    end

    local payload = jwt_obj.payload

    -- ================= CLAIM VALIDATION =================
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
    -- FIX: red:set(..., "NX") trả về:
    --   "OK"       → key chưa tồn tại, set thành công  → request hợp lệ
    --   ngx.null   → key đã tồn tại (NX condition fail) → đây là REPLAY
    if red and payload.jti then
        local ttl = payload.exp - now
        if ttl > 0 then
            local res, set_err = red:set(REPLAY_PREFIX .. payload.jti, 1, "NX", "EX", ttl)

            if set_err then
                ngx.log(ngx.ERR, "[JWT] Redis SET NX error: ", set_err)
            elseif res == ngx.null then
                -- Key đã tồn tại → jti này đã được dùng → REPLAY
                ngx.ctx.risk_score = ngx.ctx.risk_score + SCORE_REPLAY
                table.insert(ngx.ctx.flags, "jwt_replay")

                log_once("jwt_rp:" .. ip, "[JWT] Replay detected IP=" .. ip)

                red:set_keepalive(10000, 100)
                return nil
            end
            -- res == "OK" → jti mới, request hợp lệ, tiếp tục
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
