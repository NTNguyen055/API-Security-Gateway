-- =============================================================================
-- File: nginx/lua/utils.lua
-- Chức năng: Chứa các hàm tiện ích dùng chung cho toàn bộ module Security
-- =============================================================================

local _M = {}

-- ── Kiểm tra IPv4 hợp lệ ──────────────────────────────────────────────
function _M.is_valid_ipv4(ip)
    if not ip or type(ip) ~= "string" then return false end
    local chunks = {ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")}
    if #chunks == 4 then
        for _, v in ipairs(chunks) do
            if tonumber(v) > 255 then return false end
        end
        return true
    end
    return false
end

-- ── Kiểm tra IPv6 hợp lệ (Chống bypass bằng ký tự ":") ────────────────
function _M.is_valid_ipv6(ip)
    if not ip or #ip < 2 or #ip > 45 then return false end
    
    -- Loại bỏ dấu ngoặc vuông nếu có (Ví dụ: [::1])
    ip = ip:match("^%[(.+)%]$") or ip
    local _, colons = ip:gsub(":", "")
    
    return colons >= 2 and colons <= 7 and not ip:match("[^0-9a-fA-F:]")
end

-- ── Kiểm tra IP hợp lệ (Gom chung IPv4 và IPv6) ───────────────────────
function _M.is_valid_ip(ip)
    return _M.is_valid_ipv4(ip) or _M.is_valid_ipv6(ip)
end

-- ── Kiểm tra IP nội bộ (Private) / Mạng ảo ────────────────────────────
function _M.is_private_ip(ip)
    -- Tinh chỉnh nhỏ: Check nil ngay từ đầu cho nhất quán style
    if not ip or not _M.is_valid_ipv4(ip) then return false end

    -- Loopback và Link-local
    if ip:match("^127%.") then return true end
    if ip:match("^169%.254%.") then return true end

    -- RFC-1918 (Mạng LAN phổ thông)
    if ip:match("^10%.") then return true end
    if ip:match("^192%.168%.") then return true end

    -- Dải 0.0.0.0/8
    if ip:match("^0%.") then return true end

    -- Dải 172.16.0.0/12 (Docker và AWS VPC thường dùng dải này)
    local b = ip:match("^172%.(%d+)%.")
    if b then
        local n = tonumber(b)
        if n >= 16 and n <= 31 then return true end
    end

    -- Carrier-grade NAT (AWS Internal Traffic 100.64.0.0/10)
    local cgnat = ip:match("^100%.(%d+)%.")
    if cgnat then
        local n = tonumber(cgnat)
        if n >= 64 and n <= 127 then return true end
    end

    return false
end

return _M