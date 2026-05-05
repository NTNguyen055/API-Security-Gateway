local _M = {}
local math_min = math.min
local utils = require "utils"         -- Tái sử dụng module kiểm tra IP
local geo = require "resty.maxminddb" -- Sử dụng thư viện đọc file local cực nhanh

-- =============================================================================
-- CONFIG
-- =============================================================================
-- Danh sách các quốc gia được phép truy cập (Chỉ cho phép VN, US, SG, JP)
local ALLOWED_COUNTRIES = {
    ["VN"] = true,
    ["US"] = true,
    ["SG"] = true,
    ["JP"] = true,
}

-- KHUYẾN NGHỊ: Việc khởi tạo database đã được dời sang init_by_lua_block 
-- trong file nginx.conf để tối ưu hóa bộ nhớ RAM cho các Nginx Workers (Copy-on-Write).

-- =============================================================================
-- MAIN
-- =============================================================================
function _M.run(ctx)
    -- Ưu tiên client_ip từ xff_guard đã được sanitize
    local ip = (ctx.security and ctx.security.client_ip)
               or ngx.var.realip_remote_addr
               or ngx.var.remote_addr

    ctx.security         = ctx.security or {}
    ctx.security.signals = ctx.security.signals or {}

    -- Tái sử dụng utils.lua, loại bỏ code lặp lại
    if not ip or utils.is_private_ip(ip) then
        ctx.security.geo_private = true
        return
    end

    -- Đọc trực tiếp từ file MMDB nội bộ (< 1 mili-giây)
    local res, err = geo.lookup(ip)
    
    if not res then
        ngx.log(ngx.ERR, "[GEO] Failed to lookup IP: ", ip, " Err: ", err or "Unknown")
        ctx.security.geo_lookup_fail = true
        return
    end

    local country = res.country and res.country.iso_code

    if not country then
        -- Trả về nil nếu IP không có trong DB (VD: IP loopback hoặc DB cũ)
        return
    end

    ctx.security.geo_country = country

    -- Kiểm tra xem quốc gia này có nằm trong Whitelist không
    if ALLOWED_COUNTRIES[country] then
        ctx.security.geo_allowed = true
        return
    end

    -- Hard Block (Chặn đứng lập tức) những quốc gia không được phép
    ctx.security.geo_blocked = true
    ctx.security.block       = true 

    -- Tích hợp Risk Engine: Tăng thêm điểm phạt nếu trước đó đã bị tình nghi
    local base = 25
    if ctx.security.bad_bot_scanner then base = math_min(base + 10, 100) end
    if ctx.security.rate_limit_hard then base = math_min(base + 10, 100) end
    ctx.security.risk = math_min((ctx.security.risk or 0) + base, 100)

    table.insert(ctx.security.signals, "geo_block:" .. country)
    
    ngx.log(ngx.WARN, "[GEO] BLOCK country=", country, " ip=", ip)

end

return _M