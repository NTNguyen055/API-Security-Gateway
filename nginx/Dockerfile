FROM openresty/openresty:alpine-fat

# ================= BASE =================
RUN apk add --no-cache \
    ca-certificates \
    curl \
    libmaxminddb \
    && update-ca-certificates

# ================= DIR =================
RUN mkdir -p /usr/local/openresty/nginx/lua \
    /usr/local/openresty/nginx/logs \
    /etc/nginx/geoip

# ================= LUA MODULES =================
# NOTE: bỏ lua-resty-hmac (deprecated / gây lỗi build)
RUN luarocks install lua-resty-jwt 0.2.3-0 \
 && luarocks install lua-resty-http 0.17.2-0 \
 && luarocks install lua-resty-string \
 && luarocks install nginx-lua-prometheus 0.20230617-1 \
 && luarocks install lua-resty-maxminddb

# ================= GEOIP =================
COPY GeoLite2-Country.mmdb /etc/nginx/geoip/GeoLite2-Country.mmdb

# ================= CONFIG =================
COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY lua/ /usr/local/openresty/nginx/lua/

# ================= PERMISSIONS =================
RUN chmod -R 755 /usr/local/openresty/nginx/lua

# ================= VERIFY =================
RUN openresty -t

RUN resty -e "require 'cjson'; require 'resty.maxminddb'; require 'resty.jwt'; print('OK')"

# ================= PORT =================
EXPOSE 80 443 9145

# ================= RUN =================
CMD ["openresty", "-g", "daemon off;"]