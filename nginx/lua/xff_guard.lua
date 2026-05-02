local _M = {}

local ngx      = ngx
local math_min = math.min

-- Giới hạn chain để tránh header abuse
local MAX_CHAIN = 10

-- ============================================================
-- PRIVATE / RESERVED IP RANGES
-- ============================================================
local function is_private_ip(ip)
    if not ip then return false end

    -- Loopback
    if ip == "127.0.0.1" or ip == "::1" then return true end

    -- Link-local
    if ip:match("^169%.254%.") then return true end

    -- RFC-1918
    if ip:match("^10%.") then return true end
    if ip:match("^192%.168%.") then return true end

    -- 172.16.0.0/12 — dùng số học thay vì alternation (Lua không hỗ trợ |)
    local a, b = ip:match("^172%.(%d+)%.")
    if a then
        local n = tonumber(a)
        if n and n >= 16 and n <= 31 then return true end
    end

    return false
end

-- ============================================================
-- IPv4 VALIDATOR
-- ============================================================
local function is_valid_ipv4(ip)
    if not ip then return false end

    local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then return false end

    a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
    return a <= 255 and b <= 255 and c <= 255 and d <= 255
end

-- ============================================================
-- IPv6 VALIDATOR (basic — chấp nhận format chuẩn)
-- ============================================================
local function is_valid_ipv6(ip)
    if not ip then return false end
    -- Loại bỏ bracket notation [::1]
    ip = ip:match("^%[(.+)%]$") or ip
    -- Phải có ít nhất một dấu : và chỉ chứa hex + dấu :
    return ip:find(":", 1, true) and not ip:match("[^0-9a-fA-F:]")
end

-- ============================================================
-- PARSE XFF HEADER — hỗ trợ cả IPv4 và IPv6
-- ============================================================
local function parse_xff(xff)
    local ips = {}

    for ip in xff:gmatch("([^,]+)") do
        ip = ip:gsub("^%s*(.-)%s*$", "%1")

        if is_valid_ipv4(ip) or is_valid_ipv6(ip) then
            ips[#ips + 1] = ip
        end
    end

    return ips
end

-- ============================================================
-- MAIN
-- ============================================================
function _M.run(ctx)
    local xff = ngx.var.http_x_forwarded_for
    if not xff or xff == "" then
        return
    end

    ctx.security        = ctx.security or {}
    ctx.security.signals = ctx.security.signals or {}

    local ips = parse_xff(xff)

    -- ── MALFORMED HEADER ──────────────────────────────────────
    if #ips == 0 then
        ctx.security.xff_malformed = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 10, 100)
        table.insert(ctx.security.signals, "xff_malformed")
        ngx.log(ngx.WARN, "[XFF_GUARD] Malformed header | xff=", xff)
        return
    end

    -- ── TOO MANY HOPS ─────────────────────────────────────────
    if #ips > MAX_CHAIN then
        ctx.security.xff_chain_abuse = true
        ctx.security.block = true   -- hard block: chain > 10 là tấn công rõ ràng
        ctx.security.risk  = 100

        table.insert(ctx.security.signals, "xff_chain_abuse")

        ngx.log(ngx.WARN,
            "[XFF_GUARD] Chain too long: ", #ips,
            " | xff=", xff
        )
        return
    end

    -- ── PRIVATE IP IN CLIENT POSITION ─────────────────────────
    local client_ip = ips[1]

    if is_private_ip(client_ip) then
        ctx.security.xff_private_client = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 20, 100)

        table.insert(ctx.security.signals, "xff_private_client")

        ngx.log(ngx.WARN,
            "[XFF_GUARD] Private IP as client: ", client_ip
        )
    end

    -- ── LƯU CLIENT IP VÀO CTX cho các module sau dùng chung ──
    ctx.security.client_ip = client_ip

    -- ── SANITIZE HEADER ───────────────────────────────────────
    ngx.req.set_header("X-Forwarded-For", table.concat(ips, ", "))
end

return _M
