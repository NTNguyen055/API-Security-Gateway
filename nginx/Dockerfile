FROM openresty/openresty:alpine-fat

# ================= BASE =================
RUN apk add --no-cache \
    ca-certificates \
    libmaxminddb \
    && update-ca-certificates

# ================= DIR =================
RUN mkdir -p \
    /usr/local/openresty/nginx/lua \
    /usr/local/openresty/nginx/logs \
    /usr/local/openresty/lualib/resty \
    /etc/nginx/geoip

# ================= COPY VENDOR =================
COPY vendor/resty/ /usr/local/openresty/lualib/resty/
COPY vendor/prometheus.lua /usr/local/openresty/lualib/

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