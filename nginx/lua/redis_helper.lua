-- =============================================================================
-- File: nginx/lua/redis_helper.lua
-- Chức năng: Cấp phát kết nối Redis an toàn, tối ưu timeout và tự động chọn DB
-- =============================================================================

local redis = require "resty.redis"
local _M = {}

function _M.get_redis(db_index)
    local red = redis:new()
    
    -- Tối ưu Timeout (Mạng nội bộ Docker): 200ms connect, 200ms send, 500ms read
    -- Tránh tình trạng Nginx bị "treo" (block) quá lâu nếu Redis gặp sự cố
    red:set_timeouts(200, 200, 500)

    -- "redis" ở đây là tên service của container Redis trong docker-compose.yml
    local ok, err = red:connect("redis", 6379)
    if not ok then
        return nil, "connect failed: " .. tostring(err)
    end

    -- Chọn DB (Mặc định là 0 cho Gateway, để không đụng chạm DB 1 của Django)
    local db = db_index or 0
    local ok2, err2 = red:select(db)
    if not ok2 then
        return nil, "select db" .. tostring(db) .. " failed: " .. tostring(err2)
    end

    return red
end

-- Bổ sung hàm close() để quản lý Connection Pool đồng nhất toàn hệ thống
function _M.close(red)
    if red then
        -- Giữ connection trong pool tối đa 10s, pool size 100
        red:set_keepalive(10000, 100)
    end
end

return _M