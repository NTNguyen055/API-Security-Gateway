FROM openresty/openresty:1.25.3.1-alpine-fat

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

# Install libs FIRST
RUN opm get knyar/nginx-lua-prometheus \
 && opm get jkeys089/lua-resty-hmac

# Copy custom code
COPY lualib/ $LUA_LIB_DIR/
COPY lua/    $LUA_APP_DIR/
COPY geoip/  $GEOIP_DIR/
COPY nginx.conf $NGINX_DIR/conf/nginx.conf

# Verify
RUN test -f /etc/geoip/GeoLite2-Country.mmdb

RUN /usr/local/openresty/bin/resty -e "require 'resty.redis'"
RUN /usr/local/openresty/bin/resty -e "require 'resty.jwt'"
RUN /usr/local/openresty/bin/resty -e "require 'resty.limit.req'"
RUN /usr/local/openresty/bin/resty -e "require 'resty.maxminddb'"

RUN addgroup -S nginxgrp && adduser -S nginxusr -G nginxgrp

RUN mkdir -p \
        $NGINX_DIR/client_body_temp \
        $NGINX_DIR/proxy_temp \
        $NGINX_DIR/logs \
    && chown -R nginxusr:nginxgrp $NGINX_DIR $LUA_LIB_DIR $LUA_APP_DIR $GEOIP_DIR

USER nginxusr

HEALTHCHECK --interval=30s --timeout=3s \
  CMD curl -f http://127.0.0.1/health/ || exit 1

EXPOSE 80 443

CMD ["openresty", "-g", "daemon off;"]