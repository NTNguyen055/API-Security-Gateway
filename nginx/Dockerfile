FROM openresty/openresty:alpine-fat

# Cài git
RUN apk add --no-cache git

# Tạo thư mục lua
RUN mkdir -p /usr/local/openresty/nginx/lua

# lua-resty-hmac (bắt buộc cho jwt)
RUN git clone https://github.com/jkeys089/lua-resty-hmac.git /tmp/lua-resty-hmac \
 && cp /tmp/lua-resty-hmac/lib/resty/hmac.lua /usr/local/openresty/lualib/resty/

# lua-resty-jwt
RUN git clone https://github.com/SkyLothar/lua-resty-jwt.git /tmp/lua-resty-jwt \
 && cp -r /tmp/lua-resty-jwt/lib/resty/* /usr/local/openresty/lualib/resty/

# lua-resty-redis
RUN git clone https://github.com/openresty/lua-resty-redis.git /tmp/lua-resty-redis \
 && cp -r /tmp/lua-resty-redis/lib/resty/* /usr/local/openresty/lualib/resty/

# lua-resty-http
RUN git clone https://github.com/ledgetech/lua-resty-http.git /tmp/lua-resty-http \
 && cp -r /tmp/lua-resty-http/lib/resty/* /usr/local/openresty/lualib/resty/

# nginx-lua-prometheus
RUN git clone https://github.com/knyar/nginx-lua-prometheus.git /tmp/prometheus \
 && cp /tmp/prometheus/prometheus.lua /usr/local/openresty/lualib/

# lua-resty-string (cần cho jwt sha256)
RUN git clone https://github.com/openresty/lua-resty-string.git /tmp/lua-resty-string \
 && cp -r /tmp/lua-resty-string/lib/resty/* /usr/local/openresty/lualib/resty/

# lua-resty-limit-traffic (cần cho rate_limit)
RUN git clone https://github.com/openresty/lua-resty-limit-traffic.git /tmp/lua-resty-limit \
 && cp -r /tmp/lua-resty-limit/lib/resty/* /usr/local/openresty/lualib/resty/

# Copy config + lua modules
COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY lua/ /usr/local/openresty/nginx/lua/

EXPOSE 80 443

CMD ["openresty", "-g", "daemon off;"]
