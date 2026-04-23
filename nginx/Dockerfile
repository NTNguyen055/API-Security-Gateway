FROM openresty/openresty:alpine-fat

# ================= BASE =================
RUN apk add --no-cache \
    git \
    curl \
    ca-certificates \
    && update-ca-certificates

# ================= LUA DIR =================
RUN mkdir -p /usr/local/openresty/lualib/resty

# ================= LUA MODULES =================

# ---------------- HMAC ----------------
RUN git clone --depth 1 https://github.com/jkeys089/lua-resty-hmac.git /tmp/hmac \
 && cp /tmp/hmac/lib/resty/hmac.lua /usr/local/openresty/lualib/resty/ \
 && rm -rf /tmp/hmac

# ---------------- JWT ----------------
RUN git clone --depth 1 https://github.com/SkyLothar/lua-resty-jwt.git /tmp/jwt \
 && cp -r /tmp/jwt/lib/resty/* /usr/local/openresty/lualib/resty/ \
 && rm -rf /tmp/jwt

# ---------------- REDIS ----------------
RUN git clone --depth 1 https://github.com/openresty/lua-resty-redis.git /tmp/redis \
 && cp -r /tmp/redis/lib/resty/* /usr/local/openresty/lualib/resty/ \
 && rm -rf /tmp/redis

# ---------------- HTTP ----------------
RUN git clone --depth 1 https://github.com/ledgetech/lua-resty-http.git /tmp/http \
 && cp -r /tmp/http/lib/resty/* /usr/local/openresty/lualib/resty/ \
 && rm -rf /tmp/http

# ---------------- PROMETHEUS (FIXED) ----------------
RUN git clone --depth 1 https://github.com/knyar/nginx-lua-prometheus.git /tmp/prom \
 && cp -r /tmp/prom/* /usr/local/openresty/lualib/ \
 && rm -rf /tmp/prom

# ---------------- STRING ----------------
RUN git clone --depth 1 https://github.com/openresty/lua-resty-string.git /tmp/string \
 && cp -r /tmp/string/lib/resty/* /usr/local/openresty/lualib/resty/ \
 && rm -rf /tmp/string

# ---------------- LIMIT TRAFFIC ----------------
RUN git clone --depth 1 https://github.com/openresty/lua-resty-limit-traffic.git /tmp/limit \
 && cp -r /tmp/limit/lib/resty/* /usr/local/openresty/lualib/resty/ \
 && rm -rf /tmp/limit

# ================= CONFIG =================
COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY lua/ /usr/local/openresty/nginx/lua/

# ================= PERMISSIONS =================
RUN chmod -R 755 /usr/local/openresty/lualib

# ================= PORT =================
EXPOSE 80 443

# ================= RUN =================
CMD ["openresty", "-g", "daemon off;"]