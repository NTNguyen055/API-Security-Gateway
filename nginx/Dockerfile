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

# Chỉ install những gì thực sự cần
RUN opm get knyar/nginx-lua-prometheus

COPY lualib/ $LUA_LIB_DIR/
COPY lua/    $LUA_APP_DIR/
COPY geoip/  $GEOIP_DIR/
COPY nginx.conf $NGINX_DIR/conf/nginx.conf

RUN find $LUA_LIB_DIR -name "*.md" -delete

# Verify build-time
RUN /usr/local/openresty/bin/resty -e "require 'cjson'; print('cjson OK')" \
 && /usr/local/openresty/bin/resty -e "require 'resty.redis'; print('redis OK')" \
 && /usr/local/openresty/bin/resty -e "require 'resty.jwt'; print('jwt OK')" \
 && /usr/local/openresty/bin/resty -e "require 'resty.limit.req'; print('limit OK')" \
 && /usr/local/openresty/bin/resty -e "require 'resty.maxminddb'; print('maxmind OK')" \
 && /usr/local/openresty/bin/resty -e "require 'prometheus'; print('prometheus OK')"

RUN addgroup -S nginxgrp && adduser -S nginxusr -G nginxgrp

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

HEALTHCHECK --interval=30s --timeout=3s \
  CMD curl -f http://127.0.0.1/health/ || exit 1

EXPOSE 80 443

CMD ["openresty", "-g", "daemon off;"]