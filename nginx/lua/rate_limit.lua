local _M = {}

local ngx = ngx
local tonumber = tonumber
local math_min = math.min

local lim

local function get_limiter()
    if lim then
        return lim
    end

    local limit_req = require "resty.limit.req"

    -- [FIX] Đưa os.getenv vào trong hàm để đảm bảo load đúng giá trị
    local rate  = tonumber(os.getenv("RATE_LIMIT_RPS"))   or 10
    local burst = tonumber(os.getenv("RATE_LIMIT_BURST")) or 20

    local l, err = limit_req.new("limit_req_store", rate, burst)
    if not l then
        ngx.log(ngx.ERR, "[RATE_LIMIT] Init failed: ", err)
        return nil
    end

    lim = l
    return lim
end

-- [FIX] Đã di chuyển các hằng số AUTO_BL_* vào bên trong hàm auto_blacklist

local function auto_blacklist(ip, ctx)
    local counter_store = ngx.shared.rl_counter
    if not counter_store then return end

    -- [FIX] Đọc config môi trường ngay lúc thực thi
    local AUTO_BL_THRESHOLD = tonumber(os.getenv("AUTO_BL_THRESHOLD")) or 5
    local AUTO_BL_WINDOW    = tonumber(os.getenv("AUTO_BL_WINDOW"))    or 60
    local AUTO_BL_DURATION  = tonumber(os.getenv("AUTO_BL_DURATION"))  or 3600

    local count = counter_store:incr("rl:" .. ip, 1, 0, AUTO_BL_WINDOW)
    if not count then return end

    if count < AUTO_BL_THRESHOLD or (ctx.security.risk or 0) < 50 then
        return
    end

    local lock = counter_store:add("bl_lock:" .. ip, true, 5)
    if not lock then
        return
    end

    local bl_cache = ngx.shared.ip_blacklist
    if bl_cache then
        bl_cache:set(ip, true, AUTO_BL_DURATION)
    end

    ngx.timer.at(0, function(premature, target_ip, duration)
        if premature then return end

        local redis = require "resty.redis"
        local red = redis:new()
        red:set_timeouts(100, 100, 100)

        -- [FIX] Dùng REDIS_URL thay vì hardcode
        local host = "redis"
        local port = 6379
        local redis_url = os.getenv("REDIS_URL")
        if redis_url then
            local parsed_host, parsed_port = redis_url:match("redis://([^:/]+):?(%d*)")
            if parsed_host then host = parsed_host end
            if parsed_port and parsed_port ~= "" then port = tonumber(parsed_port) end
        end

        if not red:connect(host, port) then
            return
        end

        -- [FIX] Add IP vào SET 'blacklist_ips' để đồng bộ với ip_blacklist.lua
        red:sadd("blacklist_ips", target_ip)
        
        -- Vẫn giữ lại key string để tham khảo TTL nếu cần cho mục đích khác
        red:set("blacklist_ttl:" .. target_ip, 1, "EX", duration)

        red:set_keepalive(10000, 100)

        ngx.log(ngx.WARN, "[AUTO_BL] BLACKLISTED: ", target_ip)
    end, ip, AUTO_BL_DURATION)

    counter_store:delete("rl:" .. ip)
end

function _M.run(ctx)
    local limiter = get_limiter()
    if not limiter then
        return
    end

    local ip = ngx.var.realip_remote_addr or ngx.var.remote_addr
    local uri = ngx.var.uri or ""
    local key = ip .. ":" .. uri

    ctx.security = ctx.security or {}
    ctx.security.signals = ctx.security.signals or {}

    local delay, err = limiter:incoming(key, true)

    if not delay then
        if err == "rejected" then
            ctx.security.rate_limit_hard = true
            ctx.security.risk = math_min((ctx.security.risk or 0) + 30, 100)

            table.insert(ctx.security.signals, "rate_limit_hard")

            ngx.log(ngx.WARN, "[RATE_LIMIT] HARD IP=", ip)

            auto_blacklist(ip, ctx)
            return
        end

        ngx.log(ngx.ERR, "[RATE_LIMIT] Error: ", err)
        return
    end

    if delay > 0 then
        ngx.sleep(delay)

        ctx.security.rate_limit_burst = true
        ctx.security.risk = math_min((ctx.security.risk or 0) + 15, 100)

        table.insert(ctx.security.signals, "rate_limit_burst")

        ngx.log(ngx.WARN,
            "[RATE_LIMIT] BURST IP=", ip,
            " delay=", string.format("%.3f", delay)
        )

        return
    end

    ctx.security.rate_ok = true
    table.insert(ctx.security.signals, "rate_ok")
end

return _M