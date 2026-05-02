FROM openresty/openresty:alpine-fat

# ================= SYSTEM =================
RUN apk add --no-cache \
    ca-certificates \
    libmaxminddb \
    openssl \
    && update-ca-certificates

# ================= DIR =================
RUN mkdir -p \
    /usr/local/openresty/nginx/lua \
    /usr/local/openresty/nginx/logs \
    /usr/local/openresty/lualib/resty \
    /etc/nginx/geoip \
    /etc/letsencrypt/live/dacn3.duckdns.org

# ================= VENDOR (OFFLINE LUA LIBS) =================
COPY vendor/resty/ /usr/local/openresty/lualib/resty/
COPY vendor/prometheus.lua /usr/local/openresty/lualib/

# ================= GEOIP =================
COPY GeoLite2-Country.mmdb /etc/nginx/geoip/

# ================= CONFIG =================
COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY lua/ /usr/local/openresty/nginx/lua/

# ================= FAKE SSL (CHO CI/CD) =================
# Fix lỗi: nginx -t fail vì không có cert
RUN openssl req -x509 -nodes -days 365 \
    -subj "/CN=localhost" \
    -newkey rsa:2048 \
    -keyout /etc/letsencrypt/live/dacn3.duckdns.org/privkey.pem \
    -out /etc/letsencrypt/live/dacn3.duckdns.org/fullchain.pem

# ================= PERMISSIONS =================
RUN chmod -R 755 /usr/local/openresty

# ================= PORT =================
EXPOSE 80 443 9145

# ================= RUN =================
CMD ["openresty", "-g", "daemon off;"]