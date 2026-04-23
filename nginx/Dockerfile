FROM openresty/openresty:alpine-fat

# Cài git
RUN apk add --no-cache git

# Tạo thư mục lua
RUN mkdir -p /usr/local/openresty/nginx/lua

# Clone các lib cần thiết
RUN git clone https://github.com/SkyLothar/lua-resty-jwt.git /tmp/lua-resty-jwt \
 && cp -r /tmp/lua-resty-jwt/lib/resty/* /usr/local/openresty/lualib/resty/

RUN git clone https://github.com/openresty/lua-resty-redis.git /tmp/lua-resty-redis \
 && cp -r /tmp/lua-resty-redis/lib/resty/* /usr/local/openresty/lualib/resty/

RUN git clone https://github.com/ledgetech/lua-resty-http.git /tmp/lua-resty-http \
 && cp -r /tmp/lua-resty-http/lib/resty/* /usr/local/openresty/lualib/resty/

RUN git clone https://github.com/knyar/nginx-lua-prometheus.git /tmp/prometheus \
 && cp /tmp/prometheus/prometheus.lua /usr/local/openresty/lualib/

# Copy config + lua modules của bạn
COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY lua/ /usr/local/openresty/nginx/lua/

EXPOSE 80 443

CMD ["openresty", "-g", "daemon off;"]