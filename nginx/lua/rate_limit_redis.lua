local _M = {}

local ngx      = ngx
local tonumber = tonumber
local math_min = math.min

-- Đọc trong function để tránh nil khi module load trước env inject
local function get_config()
    return {
        limit  = tonumber(os.getenv("REDIS_RATE_LIMIT")) or 30,
        window = tonumber(os.getenv("REDIS_RL_WINDOW"))  or 60,
    }
end

-- ============================================================
-- Atomic INCR + EXPIRE script — tránh race condition
-- ============================================================
local REDIS_SCRIPT = [[
local key    = KEYS[1]
local window = tonumber(ARGV[1])
local current = redis.call('INCR', key)
if current == 1 then
    redis.call('EXPIRE', key, window)
end
return current
]]

-- ============================================================
-- REDIS HELPER — timeout tăng lên 200/500ms, db 0
-- ============================================================
local function get_redis()
    local redis = require "resty.redis"
    local red   = redis:new()

    red:set_timeouts(200, 200, 500)

    local ok, err = red:connect("redis", 6379)
    if not ok then
        return nil, err
    end

    return red
end

-- ============================================================
-- MAIN
-- ============================================================
function _M.run(ctx)
    -- Ưu tiên dùng client_ip đã normalize từ xff_guard
    local ip  = (ctx.security and ctx.security.client_ip)
                or ngx.var.realip_remote_addr
                or ngx.var.remote_addr
    local uri = ngx.var.uri or ""

    ctx.security         = ctx.security or {}
    ctx.security.signals = ctx.security.signals or {}

    local cfg = get_config()

    -- ── LOCAL THROTTLE (shared dict rl_counter) ───────────────
    -- Dùng rl_counter (đã khai báo trong nginx.conf) thay vì rl_cache
    -- để tránh hit Redis mỗi request khi risk thấp
    local throttle = ngx.shared.rl_counter
    if throttle and (ctx.security.risk or 0) < 30 then
        local throttle_key = "rrl_throttle:" .. ip
        local hit = throttle:get(throttle_key)
        if hit then
            ctx.security.redis_rate_ok = true
            return
        end
        throttle:set(throttle_key, 1, 1)  -- TTL 1s, dùng số 1 không phải boolean
    end

    -- ── REDIS ─────────────────────────────────────────────────
    local red, err = get_redis()

    if not red then
        ngx.log(ngx.WARN, "[REDIS_RL] Redis down: ", err)
        ctx.security.redis_rl_fail = true

        if ctx.security.rate_limit_hard then
            ctx.security.risk = math_min((ctx.security.risk or 0) + 15, 100)
        else
            ctx.security.risk = math_min((ctx.security.risk or 0) + 5, 100)
        end
        return
    end

    -- Key theo IP (không có URI để tránh bypass bằng rotate URI)
    -- Thêm key per-IP:URI để tracking granular hơn
    local window_id  = math.floor(ngx.time() / cfg.window)
    local key_ip     = "rrl:" .. ip .. ":" .. window_id
    local key_ip_uri = "rrl:" .. ip .. ":" .. uri .. ":" .. window_id

    -- Đếm cả 2 counter cùng lúc qua pipeline
    red:init_pipeline()
    red:eval(REDIS_SCRIPT, 1, key_ip,     cfg.window)
    red:eval(REDIS_SCRIPT, 1, key_ip_uri, cfg.window)
    local results, pipe_err = red:commit_pipeline()

    red:set_keepalive(10000, 100)

    if not results then
        ngx.log(ngx.ERR, "[REDIS_RL] Pipeline error: ", pipe_err)
        ctx.security.redis_rl_error = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 10, 100)
        return
    end

    -- Lấy count lớn hơn trong 2 counter (IP global hoặc IP+URI)
    local count_ip     = tonumber(results[1]) or 0
    local count_ip_uri = tonumber(results[2]) or 0
    local count        = math.max(count_ip, count_ip_uri)
    local limit        = cfg.limit

    -- ── NORMAL (<70% limit) ───────────────────────────────────
    if count <= limit * 0.7 then
        ctx.security.redis_rate_ok = true
        table.insert(ctx.security.signals, "redis_rate_ok")
        return
    end

    -- ── WARNING (70%~100%) ────────────────────────────────────
    if count <= limit then
        ctx.security.redis_rate_warn = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 10, 100)
        table.insert(ctx.security.signals, "redis_rate_warn")

        ngx.log(ngx.WARN,
            "[REDIS_RL] WARN ip=", ip,
            " count=", count, "/", limit
        )
        return
    end

    -- ── EXCEEDED (>100%) ──────────────────────────────────────
    ctx.security.redis_rate_exceeded = true
    ctx.security.block               = true   -- hard block khi vượt limit
    ctx.security.risk                = math_min((ctx.security.risk or 0) + 20, 100)

    table.insert(ctx.security.signals, "redis_rate_exceeded")

    ngx.log(ngx.WARN,
        "[REDIS_RL] EXCEEDED ip=", ip,
        " count=", count, "/", limit,
        " uri=", uri
    )

    if metric_blocked then
        metric_blocked:inc(1, {"redis_rate_limit"})
    end
end

return _M
