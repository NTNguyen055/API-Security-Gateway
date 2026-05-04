local _M = {}
local ngx = ngx
local math_min = math.min

-- Gọi thư viện tiện ích để dùng chung các hàm kiểm tra IP (Thay thế cho 40 dòng code cũ)
local utils = require "utils" 

-- =========================================================================
-- PARSER
-- =========================================================================
local function parse_xff(xff_str)
    local ips = {}
    if not xff_str or xff_str == "" then return ips end
    for ip in xff_str:gmatch("[^,]+") do
        ip = ip:match("^%s*(.-)%s*$")
        if ip and ip ~= "" then table.insert(ips, ip) end
    end
    return ips
end

-- =========================================================================
-- MAIN
-- =========================================================================
function _M.run(ctx)
    local xff = ngx.var.http_x_forwarded_for
    ctx.security = ctx.security or {}
    ctx.security.signals = ctx.security.signals or {}

    -- Lưu thêm remote_addr chuẩn để cross-check với ips[1]
    ctx.security.remote_addr = ngx.var.remote_addr

    -- Nếu không có header XFF, lấy thẳng IP kết nối thực tế
    if not xff then
        ctx.security.client_ip = ngx.var.remote_addr
        ngx.req.set_header("X-Real-IP", ctx.security.client_ip)
        return
    end

    local ips = parse_xff(xff)

    -- 1. HARD BLOCK: XFF Chain Abuse (Hơn 10 proxies - Bắn phá bằng tool)
    if #ips > 10 then
        ctx.security.xff_chain_abuse = true
        ctx.security.block = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 100, 100)
        table.insert(ctx.security.signals, "xff_chain_abuse")
        ngx.log(ngx.WARN, "[XFF] Chain abuse detected. Length: ", #ips)
        return
    end

    local valid_ips = {}
    local has_malformed = false

    -- Lọc danh sách IP hợp lệ thông qua utils
    for i, ip in ipairs(ips) do
        if utils.is_valid_ip(ip) then
            table.insert(valid_ips, ip)
        else
            has_malformed = true
        end
    end

    -- 2. TÍN HIỆU: Malformed XFF (Chèn ký tự lạ vào header)
    if has_malformed then
        ctx.security.xff_malformed = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 30, 100)
        table.insert(ctx.security.signals, "xff_malformed")
    end

    if #valid_ips == 0 then
        ctx.security.client_ip = ngx.var.remote_addr
        ngx.req.set_header("X-Real-IP", ctx.security.client_ip)
        return
    end

    -- Client IP theo nguyên tắc XFF là IP hợp lệ đầu tiên
    local client_ip = valid_ips[1]

    -- Tăng Risk Score lên 40 cho Private IP để chặn triệt để hành vi giả mạo IP nội bộ
    if utils.is_private_ip(client_ip) then
        ctx.security.xff_private_client = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 40, 100)
        table.insert(ctx.security.signals, "xff_private_client")
    end

    -- 3. SANITIZE & SET HEADERS
    -- Lọc lại header XFF để loại bỏ garbage/mã độc trước khi đẩy xuống Django
    local sanitized_xff = table.concat(valid_ips, ", ")
    ngx.req.set_header("X-Forwarded-For", sanitized_xff)

    -- Đồng bộ X-Real-IP cho Django để Django luôn nhận được IP sạch
    ngx.req.set_header("X-Real-IP", client_ip)

    ctx.security.client_ip = client_ip
end

return _M