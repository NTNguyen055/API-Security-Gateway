local _M = {}

-- ✅ NOTE về Regex flags:
-- Flag "j"  = PCRE mode (bật JIT compiler của LuaJIT, tốc độ nhanh hơn ~5-10x)
-- Flag "o"  = compile pattern 1 lần duy nhất, cache lại (không recompile mỗi request)
-- Flag "jo" = kết hợp cả hai → BẮT BUỘC dùng "jo" ở đây vì:
--   (1) \b (word boundary) là cú pháp PCRE, KHÔNG phải Lua standard pattern
--   (2) Nếu dùng flag "" (không có "j"), \b sẽ không được nhận diện → match sai
-- Tất cả ngx.re.find/match trong file này đều phải dùng "jo".

-- Tier 1 — Scanner độc hại: block ngay 403
-- \b đảm bảo không false-positive: "curl" trong "scurl" sẽ không bị match
local scanner_pattern = [[\b(sqlmap|nikto|nmap|zgrab|masscan|nuclei|dirbuster|gobuster)\b]]

-- Tier 2 — Dev tools hợp lệ: allow nhưng log để audit
local dev_pattern     = [[\b(curl|wget|python-requests|postmanruntime|insomnia|httpie)\b]]

function _M.run()
    local ip = ngx.var.remote_addr

    -- Đọc UA trước khi or "" để check nil/empty đúng
    local ua = ngx.var.http_user_agent

    -- Tier 3: UA rỗng hoặc nil → 403
    -- Phải check TRƯỚC khi gán or "" vì sau đó ua luôn là string
    if not ua or ua == "" then
        ngx.log(ngx.WARN, "[BAD_BOT] Empty UA IP: ", ip)
        if metric_blocked then metric_blocked:inc(1, {"empty_ua"}) end
        return 403
    end

    -- Whitelist health check — sau khi đã confirm UA không rỗng
    if ua:find("HealthChecker", 1, true) then
        return nil
    end

    local ua_lower = ua:lower()

    -- Tier 1: scanner độc hại → 403
    if ngx.re.find(ua_lower, scanner_pattern, "jo") then
        ngx.log(ngx.WARN, "[BAD_BOT] Scanner blocked: ", ua, " IP: ", ip)
        if metric_blocked then metric_blocked:inc(1, {"bad_bot"}) end
        return 403
    end

    -- Tier 2: dev tools → allow + log (curl, Postman, wget...)
    if ngx.re.find(ua_lower, dev_pattern, "jo") then
        ngx.log(ngx.INFO, "[BAD_BOT] Dev tool allowed: ", ua, " IP: ", ip)
        return nil
    end

    return nil
end

return _M
