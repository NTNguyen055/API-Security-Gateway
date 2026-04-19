FROM openresty/openresty:alpine-fat

RUN luarocks install lua-resty-jwt \
 && luarocks install lua-resty-redis \
 && luarocks install lua-resty-http

# Tạo thư mục riêng
RUN mkdir -p /usr/local/openresty/nginx/lua

# copy vào đúng chỗ
COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY lua/ /usr/local/openresty/nginx/lua/

EXPOSE 80 443

CMD ["openresty", "-g", "daemon off;"]