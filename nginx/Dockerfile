FROM openresty/openresty:1.25.3.1-alpine-fat

# ✅ BUILD-TIME METADATA
ARG BUILD_DATE
ARG GIT_COMMIT
LABEL org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${GIT_COMMIT}" \
      org.opencontainers.image.title="api-security-gateway" \
      org.opencontainers.image.description="OpenResty + Lua adaptive security gateway"

# ✅ GROUP install → 1 layer duy nhất, tránh cache bloat
RUN apk add --no-cache \
        ca-certificates \
        curl \
        tzdata \
        libmaxminddb \
    && update-ca-certificates

ENV LUA_LIB_DIR=/usr/local/openresty/lualib \
    LUA_APP_DIR=/usr/local/openresty/nginx/lua \
    GEOIP_DIR=/etc/geoip \
    NGINX_DIR=/usr/local/openresty/nginx

RUN mkdir -p $LUA_LIB_DIR $LUA_APP_DIR $GEOIP_DIR

# ✅ Install OPM packages trước (layer cache ổn định hơn)
RUN opm get knyar/nginx-lua-prometheus \
 && opm get jkeys089/lua-resty-hmac

# ✅ Copy custom libs / lua / config / geoip
COPY lualib/ $LUA_LIB_DIR/
COPY lua/     $LUA_APP_DIR/
COPY geoip/   $GEOIP_DIR/
COPY nginx.conf $NGINX_DIR/conf/nginx.conf

# ✅ VERIFY: GeoIP DB và lib load được
RUN test -f /etc/geoip/GeoLite2-Country.mmdb

RUN /usr/local/openresty/bin/resty -e "require 'resty.redis'"
RUN /usr/local/openresty/bin/resty -e "require 'resty.jwt'"
RUN /usr/local/openresty/bin/resty -e "require 'resty.limit.req'"
RUN /usr/local/openresty/bin/resty -e "require 'resty.maxminddb'"

# ✅ VERIFY nginx.conf syntax trước khi build xong
RUN openresty -t -c $NGINX_DIR/conf/nginx.conf 2>&1 | grep -v "^nginx:" || true

# ✅ Tạo user/group không có shell (security hardening)
RUN addgroup -S nginxgrp \
 && adduser -S -H -s /sbin/nologin nginxusr -G nginxgrp

# ✅ Tạo đủ thư mục temp/log mà nginx cần; gán quyền 1 lần
RUN mkdir -p \
        $NGINX_DIR/client_body_temp \
        $NGINX_DIR/proxy_temp \
        $NGINX_DIR/fastcgi_temp \
        $NGINX_DIR/uwsgi_temp \
        $NGINX_DIR/scgi_temp \
        $NGINX_DIR/logs \
    && chown -R nginxusr:nginxgrp \
        $NGINX_DIR \
        $LUA_LIB_DIR \
        $LUA_APP_DIR \
        $GEOIP_DIR \
    && chmod 750 $NGINX_DIR/logs   # ✅ tránh log readable bởi others

# ✅ Drop root TRƯỚC khi expose
USER nginxusr

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD curl -sf -A "HealthChecker/1.0" http://127.0.0.1/health/ || exit 1

EXPOSE 80 443

# ✅ Dùng exec form (không qua shell), tránh PID 1 = sh
CMD ["openresty", "-g", "daemon off;"]
