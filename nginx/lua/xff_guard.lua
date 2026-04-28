local _M = {}

-- ============================================================
-- XFF GUARD — FINAL (STRICT + CORRECT CHAIN VALIDATION)
-- ============================================================

local ngx = ngx
local math_min = math.min

-- ============================================================
-- TRUSTED PROXIES (EXACT MATCH ONLY)
-- ============================================================

local TRUSTED_PROXIES = {
    ["127.0.0.1"] = true,
    ["::1"] = true,
    ["172.17.0.1"] = true,
}

-- ============================================================
-- SIMPLE IPv4 VALIDATION (FAST)
-- ============================================================

local function is_valid_ipv4(ip)
    if not ip then return false end

    -- tránh regex nặng → parse thủ công
    local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then return false end

    a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)

    return a <= 255 and b <= 255 and c <= 255 and d <= 255
end

-- ============================================================
-- PARSE XFF
-- ============================================================

local function parse_xff(xff)
    local ips = {}

    for ip in xff:gmatch("([^,]+)") do
        ip = ip:gsub("^%s*(.-)%s*$", "%1")

        if is_valid_ipv4(ip) then
            ips[#ips + 1] = ip
        end
    end

    return ips
end

-- ============================================================
-- MAIN
-- ============================================================

function _M.run(ctx)
    local real_ip = ngx.var.remote_addr
    local xff     = ngx.var.http_x_forwarded_for

    if not xff or xff == "" then
        return
    end

    ctx.security = ctx.security or {}

    local ips = parse_xff(xff)

    -- ========================================================
    -- MALFORMED HEADER
    -- ========================================================
    if #ips == 0 then
        ctx.security.xff_malformed = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 10, 100)
        return
    end

    local spoofed = false

    -- ========================================================
    -- CASE 1: CLIENT (NOT PROXY) SENDING XFF → SPOOF
    -- ========================================================
    if not TRUSTED_PROXIES[real_ip] then
        spoofed = true
    else
        -- ====================================================
        -- CASE 2: VALID PROXY → CHECK CHAIN
        -- ====================================================

        local last_ip = ips[#ips]

        -- proxy cuối phải match TCP source
        if last_ip ~= real_ip then
            spoofed = true
        end
    end

    -- ========================================================
    -- EMIT SIGNAL
    -- ========================================================
    if spoofed then
        ctx.security.xff_spoof = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 30, 100)

        ngx.log(ngx.WARN,
            "[XFF_GUARD] Spoof | real_ip=", real_ip,
            " | xff=", xff
        )
        return
    end

    -- ========================================================
    -- SANITIZE HEADER (TRUST FIRST IP = CLIENT)
    -- ========================================================
    local client_ip = ips[1]

    ngx.req.set_header("X-Forwarded-For", client_ip)
end

return _M