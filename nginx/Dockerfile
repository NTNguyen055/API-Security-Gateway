FROM openresty/openresty:1.25.3.1-alpine-fat

# ================= BASE =================
RUN apk add --no-cache \
    ca-certificates \
    curl \
    tzdata \
    && update-ca-certificates

# ================= ENV =================
ENV LUA_LIB_DIR=/usr/local/openresty/lualib \
    LUA_APP_DIR=/usr/local/openresty/nginx/lua \
    GEOIP_DIR=/etc/geoip \
    NGINX_DIR=/usr/local/openresty/nginx

# ================= DIR =================
RUN mkdir -p $LUA_LIB_DIR $LUA_APP_DIR $GEOIP_DIR

# ================= INSTALL LUA DEPS VIA OPM =================
RUN opm get jkeys089/lua-resty-hmac \
 && opm get SkyLothar/lua-resty-jwt

# ================= COPY (NO GIT CLONE) =================
COPY lualib/ $LUA_LIB_DIR/
COPY lua/    $LUA_APP_DIR/
COPY geoip/  $GEOIP_DIR/
COPY nginx.conf $NGINX_DIR/conf/nginx.conf

# ================= CLEANUP =================
RUN find $LUA_LIB_DIR -name "*.md" -delete

# ================= VERIFY (FAIL FAST) =================
RUN /usr/local/openresty/bin/resty -e "require 'cjson'; print('cjson OK')" \
 && /usr/local/openresty/bin/resty -e "require 'resty.redis'; print('redis OK')" \
 && /usr/local/openresty/bin/resty -e "require 'resty.hmac'; print('hmac OK')" \
 && /usr/local/openresty/bin/resty -e "require 'resty.jwt'; print('jwt OK')" \
 && /usr/local/openresty/bin/resty -e "require 'resty.limit.req'; print('limit OK')" \
 && /usr/local/openresty/bin/resty -e "require 'resty.maxminddb'; print('maxmind OK')"

# ================= SECURITY (RUN NON-ROOT) =================
RUN addgroup -S nginxgrp && adduser -S nginxusr -G nginxgrp

# ================= PERMISSION =================
# Tạo trước tất cả thư mục nginx cần ghi khi runtime, rồi chown cho nginxusr
# nginx cần tạo các temp dirs này khi start: client_body_temp, proxy_temp,
# fastcgi_temp, uwsgi_temp, scgi_temp + thư mục logs
RUN mkdir -p \
        $NGINX_DIR/client_body_temp \
        $NGINX_DIR/proxy_temp \
        $NGINX_DIR/fastcgi_temp \
        $NGINX_DIR/uwsgi_temp \
        $NGINX_DIR/scgi_temp \
        $NGINX_DIR/logs \
    && chown -R nginxusr:nginxgrp \
        $NGINX_DIR/client_body_temp \
        $NGINX_DIR/proxy_temp \
        $NGINX_DIR/fastcgi_temp \
        $NGINX_DIR/uwsgi_temp \
        $NGINX_DIR/scgi_temp \
        $NGINX_DIR/logs \
        $LUA_LIB_DIR \
        $LUA_APP_DIR \
        $GEOIP_DIR \
    && chmod -R 755 \
        $LUA_LIB_DIR \
        $LUA_APP_DIR \
        $GEOIP_DIR

USER nginxusr

# ================= HEALTHCHECK =================
HEALTHCHECK --interval=30s --timeout=3s \
  CMD curl -f http://127.0.0.1/health/ || exit 1

# ================= PORT =================
EXPOSE 80 443

# ================= RUN =================
CMD ["openresty", "-g", "daemon off;"]
