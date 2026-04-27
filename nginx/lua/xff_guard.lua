local _M = {}

--[[
    XFF SPOOFING GUARD
    -------------------
    Phát hiện kẻ tấn công cố tình giả mạo X-Forwarded-For header
    để bypass IP blacklist hoặc rate-limit.

    Nguyên tắc:
    - remote_addr = IP thật của TCP connection (không thể giả)
    - X-Forwarded-For = header do client tự gửi (có thể giả)

    Nếu XFF[1] (IP đầu tiên, "nguồn gốc") KHÁC remote_addr
    mà remote_addr KHÔNG phải trusted proxy → đây là spoofing attempt.

    Hệ thống này chạy sau reverse proxy (OpenResty là proxy cuối),
    nên remote_addr luôn là IP thật của client.
]]

-- Danh sách trusted proxy được phép set XFF hợp lệ
-- (AWS ALB, CloudFront, hoặc load balancer nội bộ)
local TRUSTED_PROXIES = {
    ["127.0.0.1"]   = true,  -- localhost
    ["172.17.0.1"]  = true,  -- Docker bridge gateway
    ["172.18.0.1"]  = true,  -- Docker network gateway
    ["10.0.0.1"]    = true,  -- AWS internal (thêm nếu dùng ALB)
}

-- Kiểm tra IP có phải dải private không
local function is_private_ip(ip)
    return ngx.re.find(ip,
        [[^(127\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)]],
        "jo") ~= nil
end

function _M.run()
    local real_ip = ngx.var.remote_addr
    local xff     = ngx.var.http_x_forwarded_for

    -- Không có XFF header → bình thường, bỏ qua
    if not xff or xff == "" then
        return nil
    end

    -- Lấy IP đầu tiên trong chuỗi XFF (IP "nguồn gốc" mà client khai)
    local claimed_ip = xff:match("^%s*([^,]+)%s*")
    if not claimed_ip then
        return nil
    end
    claimed_ip = claimed_ip:gsub("%s+", "")

    -- Nếu real_ip là trusted proxy → XFF hợp lệ, bỏ qua
    if TRUSTED_PROXIES[real_ip] then
        return nil
    end

    -- Nếu real_ip là IP private (Docker internal) → bỏ qua
    if is_private_ip(real_ip) then
        return nil
    end

    -- ⚡ DETECT: real_ip KHÁC claimed_ip → client đang tự set XFF giả
    if real_ip ~= claimed_ip then
        ngx.log(ngx.WARN,
            "[XFF_GUARD] Spoofing detected! ",
            "real_ip=", real_ip,
            " claimed_xff=", claimed_ip,
            " full_xff=", xff
        )

        if metric_blocked then
            metric_blocked:inc(1, {"xff_spoof"})
        end

        -- Xóa XFF header giả, thay bằng IP thật để downstream không bị lừa
        ngx.req.set_header("X-Forwarded-For", real_ip)
        ngx.req.set_header("X-Real-IP", real_ip)

        -- Trả về 403: hành vi giả mạo header là dấu hiệu tấn công rõ ràng
        return 403
    end

    return nil
end

return _M
