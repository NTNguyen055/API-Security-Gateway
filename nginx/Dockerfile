FROM openresty/openresty:alpine-fat

# Cài các thư viện Lua non-blocking
RUN luarocks install lua-resty-jwt \
 && luarocks install lua-resty-redis \
 && luarocks install lua-resty-http

# Copy nginx.conf vào đúng vị trí OpenResty đọc
COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf

# Copy toàn bộ Lua modules vào lualib
# Cấu trúc thư mục: nginx/lua/*.lua → /usr/local/openresty/lualib/
COPY lua/ /usr/local/openresty/lualib/

# Set Lua package path — khớp với lua_package_path trong nginx.conf
ENV LUA_PATH="/usr/local/openresty/lualib/?.lua;;"

EXPOSE 80 443

CMD ["openresty", "-g", "daemon off;"]
