local _M = {}

local ngx = ngx
local tonumber = tonumber
local math_min = math.min

-- [FIX] Đã di chuyển BLOCK_THRESHOLD và LIMIT_THRESHOLD vào trong hàm run()

local DECAY_FACTOR = 0.9
local MAX_RISK     = 100

local function get_redis()
    local redis = require "resty.redis"
    local red = redis:new()

    red:set_timeouts(50, 50, 50)

    -- [FIX] Đọc cấu hình từ biến môi trường thay vì hardcode
    local host = "redis"
    local port = 6379
    local redis_url = os.getenv("REDIS_URL")
    if redis_url then
        local parsed_host, parsed_port = redis_url:match("redis://([^:/]+):?(%d*)")
        if parsed_host then host = parsed_host end
        if parsed_port and parsed_port ~= "" then port = tonumber(parsed_port) end
    end

    local ok, err = red:connect(host, port)
    if not ok then
        return nil, err
    end

    return red
end

function _M.run(ctx)
    -- [FIX] Đọc biến môi trường trong hàm để đảm bảo có data động
    local BLOCK_THRESHOLD = tonumber(os.getenv("RISK_BLOCK_THRESHOLD")) or 80
    local LIMIT_THRESHOLD = tonumber(os.getenv("RISK_LIMIT_THRESHOLD")) or 50

    local ip = ngx.var.realip_remote_addr or ngx.var.remote_addr

    ctx.security = ctx.security or {}
    local base_risk = ctx.security.risk or 0

    -- =================================================================
    -- [FIX] ĐÃ XÓA BLOCK "SIGNAL CORRELATION"
    -- Lý do: Ngăn chặn lỗi cộng dồn điểm kép (Double Counting). 
    -- Các module con đã tự động cộng điểm rủi ro vào biến ctx.security.risk.
    -- =================================================================

    -- ================= REDIS =================
    local red, err = get_redis()

    if not red then
        ngx.log(ngx.WARN, "[RISK] Redis unavailable: ", err)

        if base_risk >= BLOCK_THRESHOLD then
            return ngx.exit(403)
        elseif base_risk >= LIMIT_THRESHOLD then
            return ngx.exit(429)
        end

        ctx.security.risk_final = base_risk
        return
    end

    local key = "risk:v1:" .. ip

    local reputation = red:get(key)
    if not reputation or reputation == ngx.null then
        reputation = 0
    else
        reputation = tonumber(reputation) or 0
    end

    local final_risk = reputation * DECAY_FACTOR + base_risk

    -- momentum (quán tính phạt thêm)
    if base_risk > 30 then
        final_risk = final_risk + 10
    end

    -- forgiveness (tha thứ nếu rủi ro thấp)
    if base_risk < 10 then
        final_risk = final_risk * 0.8
    end

    final_risk = math_min(final_risk, MAX_RISK)

    red:set(key, final_risk, "EX", 3600)
    red:set_keepalive(10000, 100)

    ngx.log(ngx.INFO,
        "[RISK] ip=", ip,
        " base=", base_risk,
        " rep=", reputation,
        " final=", final_risk
    )

    if final_risk >= BLOCK_THRESHOLD then
        if metric_blocked then
            metric_blocked:inc(1, {"risk_block"})
        end
        return ngx.exit(403)
    end

    if final_risk >= LIMIT_THRESHOLD then
        if metric_blocked then
            metric_blocked:inc(1, {"risk_limit"})
        end
        return ngx.exit(429)
    end

    ctx.security.risk_final = final_risk
end

return _M