local _M = {}

local ngx      = ngx
local math_min = math.min

local CACHE_TTL_POSITIVE = 300  -- 5 phút cho IP bị blacklist
local CACHE_TTL_NEGATIVE = 30   -- 30s (tăng từ 5s) cho IP sạch

-- ============================================================
-- REDIS HELPER — timeout tăng lên 200ms, select db 0
-- (Lua dùng db 0 riêng, Django dùng db 1 — không conflict)
-- ============================================================
local function get_redis()
    local redis = require "resty.redis"
    local red   = redis:new()

    red:set_timeouts(200, 200, 500)  -- connect, send, read

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
    local ip = (ctx.security and ctx.security.client_ip)
               or ngx.var.realip_remote_addr
               or ngx.var.remote_addr

    ctx.security         = ctx.security or {}
    ctx.security.signals = ctx.security.signals or {}

    local cache = ngx.shared.ip_blacklist

    -- ── L1 CACHE (shared dict) ────────────────────────────────
    -- Dùng số 1/0 thay vì boolean (ngx.shared.dict không lưu được boolean)
    if cache then
        local val, flags = cache:get(ip)

        if val ~= nil then
            if val == 1 then
                ctx.security.ip_blacklisted = true
                ctx.security.block          = true
                ctx.security.risk           = 100

                table.insert(ctx.security.signals, "ip_blacklist_cache")
                ngx.log(ngx.WARN, "[BLACKLIST][CACHE] IP=", ip)

                if metric_blocked then
                    metric_blocked:inc(1, {"ip_blacklist_cache"})
                end
            end
            -- val == 0 → negative cache, IP sạch → return luôn
            return
        end
    end

    -- ── L2 REDIS ─────────────────────────────────────────────
    local red, err = get_redis()

    if not red then
        ngx.log(ngx.WARN, "[BLACKLIST] Redis unavailable: ", err)

        ctx.security.redis_bl_fail = true

        -- Nâng risk nếu đã có dấu hiệu đáng ngờ khác
        if ctx.security.xff_private_client or ctx.security.bad_bot_scanner then
            ctx.security.risk = math_min((ctx.security.risk or 0) + 15, 100)
        else
            ctx.security.risk = math_min((ctx.security.risk or 0) + 5, 100)
        end

        return
    end

    -- Kiểm tra trong Redis SET "blacklist_ips" (manual blacklist)
    local res, get_err = red:sismember("blacklist_ips", ip)

    -- Kiểm tra thêm auto-blacklist key từ rate_limit.lua (TTL-based)
    local auto_res
    if not get_err and (res ~= 1 and res ~= "1") then
        auto_res, get_err = red:get("blacklist:" .. ip)
    end

    red:set_keepalive(10000, 100)

    if get_err then
        ngx.log(ngx.ERR, "[BLACKLIST] Redis error: ", get_err)
        ctx.security.redis_bl_error = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 10, 100)
        return
    end

    local is_blacklisted = (res == 1 or res == "1")
                        or (auto_res and auto_res ~= ngx.null and auto_res == "1")

    if is_blacklisted then
        ngx.log(ngx.WARN, "[BLACKLIST] IP=", ip)

        -- Lưu cache với số 1 (blacklisted)
        if cache then
            cache:set(ip, 1, CACHE_TTL_POSITIVE)
        end

        ctx.security.ip_blacklisted = true
        ctx.security.block          = true
        ctx.security.risk           = 100

        table.insert(ctx.security.signals, "ip_blacklist")

        if metric_blocked then
            metric_blocked:inc(1, {"ip_blacklist"})
        end

        return
    end

    -- Negative cache: số 0 (IP sạch) — chỉ cache khi risk thấp
    if cache and (ctx.security.risk or 0) < 20 then
        cache:set(ip, 0, CACHE_TTL_NEGATIVE)
    end

    ctx.security.ip_clean = true
    table.insert(ctx.security.signals, "ip_clean")
end

return _M
