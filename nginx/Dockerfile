FROM openresty/openresty:alpine-fat

RUN luarocks install --no-cache lua-resty-jwt \
 && luarocks install --no-cache lua-resty-redis \
 && luarocks install --no-cache lua-resty-http

# Tạo thư mục lua
RUN mkdir -p /usr/local/openresty/nginx/lua

# Copy config và lua modules
COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY lua/ /usr/local/openresty/nginx/lua/

EXPOSE 80 443

CMD ["openresty", "-g", "daemon off;"]
