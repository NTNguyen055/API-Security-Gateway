FROM openresty/openresty:alpine-fat

# ================= BASE =================
RUN apk add --no-cache \
    ca-certificates \
    libmaxminddb \
    openssl \
    curl \
    && update-ca-certificates

# ================= LUA ROCKS (CÀI ĐẶT THƯ VIỆN LUA) =================
# Cài đặt các thư viện cần thiết mà base image không có sẵn
RUN luarocks install lua-resty-jwt \
    && luarocks install lua-resty-http

# ================= DIR =================
RUN mkdir -p \
    /usr/local/openresty/nginx/lua \
    /usr/local/openresty/nginx/logs \
    /usr/local/openresty/lualib/resty \
    /etc/nginx/geoip \
    /etc/letsencrypt/live/dacn3.duckdns.org

# ================= DUMMY SSL =================
RUN openssl req -x509 -nodes -days 1 -newkey rsa:2048 \
    -keyout /etc/letsencrypt/live/dacn3.duckdns.org/privkey.pem \
    -out /etc/letsencrypt/live/dacn3.duckdns.org/fullchain.pem \
    -subj "/CN=dacn3.duckdns.org"

# ================= COPY VENDOR =================
COPY vendor/resty/ /usr/local/openresty/lualib/resty/
COPY vendor/prometheus*.lua /usr/local/openresty/lualib/

# ================= GEOIP =================
COPY GeoLite2-Country.mmdb /etc/nginx/geoip/

# ================= CONFIG =================
COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY lua/ /usr/local/openresty/nginx/lua/

# ================= PERMISSION =================
RUN chmod -R 755 /usr/local/openresty/

# ================= VERIFY =================
RUN /usr/local/openresty/bin/openresty -t

# ================= PORT =================
EXPOSE 80 443 9145

# ================= RUN =================
CMD ["openresty", "-g", "daemon off;"]