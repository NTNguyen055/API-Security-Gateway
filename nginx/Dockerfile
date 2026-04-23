FROM openresty/openresty:1.21.4.1-3-alpine-fat

# ================= INSTALL LUA LIB =================
RUN luarocks install lua-resty-jwt \
 && luarocks install lua-resty-redis \
 && luarocks install lua-resty-http

# Prometheus (dùng bản stable từ GitHub)
RUN mkdir -p /usr/local/openresty/lualib/prometheus \
 && wget -O /usr/local/openresty/lualib/prometheus.lua \
    https://raw.githubusercontent.com/knyar/nginx-lua-prometheus/main/prometheus.lua

# ================= COPY CONFIG =================
RUN mkdir -p /usr/local/openresty/nginx/lua

COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY lua/ /usr/local/openresty/nginx/lua/

# ================= PORT =================
EXPOSE 80 443 9145

# ================= HEALTHCHECK =================
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD \
  wget -qO- http://localhost/health/ || exit 1

# ================= START =================
CMD ["openresty", "-g", "daemon off;"]