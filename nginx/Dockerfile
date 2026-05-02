FROM openresty/openresty:alpine-fat

# ================= BASE & C-LIBRARIES =================
RUN apk add --no-cache \
    git \
    curl \
    ca-certificates \
    libmaxminddb \
    libmaxminddb-dev \
    && update-ca-certificates

# ================= LUA DIR =================
RUN mkdir -p /usr/local/openresty/lualib/resty \
 && mkdir -p /usr/local/openresty/nginx/lua \
 && mkdir -p /usr/local/openresty/nginx/logs

# ================= LUA MODULES (LUAROCKS) =================
# FIX 1: bỏ version cứng lua-resty-hmac (0.05-0 thường fail trên alpine-fat)
# FIX 2: thêm lua-resty-string (dependency thực tế của lua-resty-jwt trên OpenResty)
RUN luarocks install lua-resty-jwt 0.2.3-0 \
 && luarocks install lua-resty-http 0.17.2-0 \
 && luarocks install lua-resty-hmac \
 && luarocks install lua-resty-string \
 && luarocks install nginx-lua-prometheus 0.20230617-1 \
 && luarocks install lua-resty-maxminddb

# ================= GEOIP DATABASE =================
RUN mkdir -p /etc/nginx/geoip/
COPY GeoLite2-Country.mmdb /etc/nginx/geoip/GeoLite2-Country.mmdb

# ================= CONFIG =================
COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY lua/ /usr/local/openresty/nginx/lua/

# ================= PERMISSIONS =================
# FIX 3: chmod cả lua/ custom scripts (không chỉ lualib)
RUN chmod -R 755 /usr/local/openresty/lualib \
 && chmod -R 755 /usr/local/openresty/nginx/lua

# ================= VERIFY =================
# FIX 4: verify nginx config hợp lệ ngay lúc build
RUN /usr/local/openresty/bin/openresty -t

# Kiểm tra các Lua module cốt lõi load thành công
RUN /usr/local/openresty/bin/resty \
    -e "require 'cjson'; require 'resty.maxminddb'; require 'resty.jwt'; print('ALL LUA MODULES LOADED OK')"

# ================= PORT =================
# FIX 5: thêm 9145 cho Prometheus metrics (docker-compose expose 127.0.0.1:9145:9145)
EXPOSE 80 443 9145

# ================= RUN =================
CMD ["openresty", "-g", "daemon off;"]
