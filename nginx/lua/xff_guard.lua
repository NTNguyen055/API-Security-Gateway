local _M = {}

local ngx = ngx
local math_min = math.min

-- giới hạn chain để tránh header abuse
local MAX_CHAIN = 10

-- private IP detect (basic)
local function is_private_ip(ip)
    return ip:match("^10%.") or
           ip:match("^192%.168%.") or
           ip:match("^172%.1[6-9]%.") or
           ip:match("^172%.2[0-9]%.") or
           ip:match("^172%.3[0-1]%.")
end

local function is_valid_ipv4(ip)
    if not ip then return false end

    local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then return false end

    a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
    return a <= 255 and b <= 255 and c <= 255 and d <= 255
end

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

function _M.run(ctx)
    local xff = ngx.var.http_x_forwarded_for
    if not xff or xff == "" then
        return
    end

    ctx.security = ctx.security or {}
    ctx.security.signals = ctx.security.signals or {} -- [FIX] Khởi tạo mảng signals

    local ips = parse_xff(xff)

    -- ========================================================
    -- MALFORMED HEADER
    -- ========================================================
    if #ips == 0 then
        ctx.security.xff_malformed = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 10, 100)
        table.insert(ctx.security.signals, "xff_spoof") -- [FIX] Bắn tín hiệu cho Risk Engine
        return
    end

    -- ========================================================
    -- TOO MANY HOPS (header abuse / evasion)
    -- ========================================================
    if #ips > MAX_CHAIN then
        ctx.security.xff_chain_abuse = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 15, 100)
        table.insert(ctx.security.signals, "xff_spoof") -- [FIX] Bắn tín hiệu cho Risk Engine

        ngx.log(ngx.WARN,
            "[XFF_GUARD] Chain too long: ", #ips,
            " | xff=", xff
        )
    end

    -- ========================================================
    -- PRIVATE IP IN CLIENT POSITION (suspicious)
    -- ========================================================
    local client_ip = ips[1]

    if is_private_ip(client_ip) then
        ctx.security.xff_private_client = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 20, 100)
        table.insert(ctx.security.signals, "xff_spoof") -- [FIX] Bắn tín hiệu cho Risk Engine

        ngx.log(ngx.WARN,
            "[XFF_GUARD] Private IP as client: ", client_ip
        )
    end

    -- ========================================================
    -- [FIX] ĐÃ XÓA NGX.REQ.SET_HEADER 
    -- Nginx đã tự động xử lý chuẩn hóa bằng $remote_addr ở phần proxy pass, 
    -- việc set lại ở đây là dư thừa và làm chậm tiến trình Lua.
    -- ========================================================
end

return _M