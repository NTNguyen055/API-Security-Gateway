local _M = {}

local ngx      = ngx
local math_min = math.min
local cjson    = require "cjson.safe"

-- =============================================================================
-- CONFIG
-- =============================================================================
local ALLOWED_COUNTRIES = {
    ["VN"] = true,
    ["US"] = true,
    ["SG"] = true,
    ["JP"] = true,
}

local GEO_CACHE_TTL = 86400  -- 24h cho kết quả lookup thành công
local GEO_FAIL_TTL  = 300    -- NÂNG CẤP: 5 phút (tăng từ 60s) cho lookup fail
                              -- tránh spam ip-api.com khi API tạm down
local GEO_TIMEOUT   = 800    -- NÂNG CẤP: 800ms (tăng từ 500ms)
local GEO_LOCK_TTL  = 10     -- NÂNG CẤP: 10s (tăng từ 5s) để đủ thời gian lookup

-- =============================================================================
-- PRIVATE IP CHECK — FIX: dùng số học cho 172.16-31, không dùng | alternation
-- =============================================================================
local function is_private_ip(ip)
    if not ip then return false end

    -- Loopback
    if ip == "127.0.0.1" or ip == "::1" then return true end

    -- Link-local
    if ip:match("^169%.254%.") then return true end

    -- RFC-1918
    if ip:match("^10%.") then return true end
    if ip:match("^192%.168%.") then return true end

    -- 172.16.0.0/12 — số học thay vì alternation
    local b = ip:match("^172%.(%d+)%.")
    if b then
        local n = tonumber(b)
        if n and n >= 16 and n <= 31 then return true end
    end

    return false
end

-- =============================================================================
-- GEO LOOKUP — FIX: fail-close thay vì fail-open
-- Khi lookup thất bại → không cache "A" (allow), giữ nguyên để retry
-- =============================================================================
local function lookup_country(ip)
    local http  = require "resty.http"
    local httpc = http.new()

    httpc:set_timeout(GEO_TIMEOUT)

    local url = "http://ip-api.com/json/" .. ip .. "?fields=countryCode,status"

    local res, err = httpc:request_uri(url, {
        method    = "GET",
        keepalive = true,
        keepalive_timeout = 60000,
        keepalive_pool    = 10,
    })

    if not res then
        return nil, "http_error:" .. tostring(err)
    end

    if res.status ~= 200 then
        return nil, "http_status:" .. tostring(res.status)
    end

    local data = cjson.decode(res.body)
    if not data then
        return nil, "json_decode_error"
    end

    if data.status ~= "success" then
        -- ip-api trả về status != success cho private/reserved IP
        return "PRIVATE", nil
    end

    if not data.countryCode or data.countryCode == "" then
        return nil, "empty_country_code"
    end

    return data.countryCode, nil
end

-- =============================================================================
-- APPLY BLOCK — tập trung logic set ctx khi bị block
-- =============================================================================
local function apply_block(ctx, ip, country, from_cache)
    local base = 25
    if ctx.security.bad_bot_scanner then base = math_min(base + 10, 100) end
    if ctx.security.rate_limit_hard  then base = math_min(base + 10, 100) end

    ctx.security.geo_blocked = true
    ctx.security.geo_country = country
    ctx.security.risk = math_min((ctx.security.risk or 0) + base, 100)

    table.insert(ctx.security.signals, "geo_block")

    local src = from_cache and "[CACHE]" or ""
    ngx.log(ngx.WARN,
        "[GEO]", src, " BLOCK country=", country,
        " ip=", ip
    )

    if metric_blocked then
        metric_blocked:inc(1, {"geo_block"})
    end
end

-- =============================================================================
-- MAIN
-- =============================================================================
function _M.run(ctx)
    -- Ưu tiên client_ip từ xff_guard
    local ip = (ctx.security and ctx.security.client_ip)
               or ngx.var.realip_remote_addr
               or ngx.var.remote_addr

    ctx.security         = ctx.security or {}
    ctx.security.signals = ctx.security.signals or {}

    -- Private IP → skip geo lookup
    if is_private_ip(ip) then
        ctx.security.geo_private = true
        return
    end

    local cache = ngx.shared.geo_cache
    if not cache then
        ctx.security.geo_cache_missing = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 5, 100)
        return
    end

    -- ── L1 CACHE HIT ─────────────────────────────────────────
    local cached = cache:get(ip)

    if cached then
        if cached == "A" then
            ctx.security.geo_allowed = true
            return
        end

        if cached == "FAIL" then
            -- Đang trong fail window → skip, jangan block
            ctx.security.geo_lookup_pending = true
            return
        end

        -- Format: "B:<countryCode>"
        if cached:sub(1, 2) == "B:" then
            local country = cached:sub(3)
            apply_block(ctx, ip, country, true)
        end
        return
    end

    -- ── LOCK để chỉ 1 request lookup API cùng lúc cho mỗi IP ─
    -- FIX: dùng số 1 thay vì boolean
    local lock_key = "geo_lock:" .. ip
    local locked, _ = cache:add(lock_key, 1, GEO_LOCK_TTL)

    if not locked then
        -- Request khác đang lookup → bỏ qua geo check cho request này
        -- (an toàn hơn là block nhầm)
        ctx.security.geo_lookup_pending = true
        return
    end

    -- ── API LOOKUP ────────────────────────────────────────────
    local country, err = lookup_country(ip)

    -- FIX: Fail-close — khi lỗi KHÔNG cache "A"
    -- Thay vào đó cache "FAIL" để các request trong GEO_FAIL_TTL
    -- biết đang trong fail window, không spam API
    if not country then
        cache:set(ip, "FAIL", GEO_FAIL_TTL)

        ctx.security.geo_lookup_fail = true

        local base = 5
        if ctx.security.rate_limit_hard then base = math_min(base + 10, 100) end
        ctx.security.risk = math_min((ctx.security.risk or 0) + base, 100)

        ngx.log(ngx.WARN,
            "[GEO] Lookup failed ip=", ip,
            " err=", tostring(err)
        )
        return
    end

    -- Private hoặc country được phép
    if country == "PRIVATE" or ALLOWED_COUNTRIES[country] then
        cache:set(ip, "A", GEO_CACHE_TTL)
        ctx.security.geo_allowed = true
        ctx.security.geo_country = country
        return
    end

    -- Bị chặn
    cache:set(ip, "B:" .. country, GEO_CACHE_TTL)
    apply_block(ctx, ip, country, false)
end

return _M
