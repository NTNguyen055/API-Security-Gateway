FROM openresty/openresty:alpine-fat

# Cài các thư viện Lua non-blocking
# --no-cache tránh dùng cache cũ khi rebuild image
RUN luarocks install --no-cache lua-resty-jwt \
 && luarocks install --no-cache lua-resty-redis \
 && luarocks install --no-cache lua-resty-http

# Copy nginx.conf vào đúng vị trí OpenResty đọc
COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf

# Copy toàn bộ Lua modules vào lualib
# Cấu trúc thư mục: nginx/lua/*.lua → /usr/local/openresty/lualib/
COPY lua/ /usr/local/openresty/lualib/

# Set Lua package path — khớp với lua_package_path trong nginx.conf
ENV LUA_PATH="/usr/local/openresty/lualib/?.lua;;"

# Validate nginx config khi build — phát hiện lỗi cú pháp sớm
# trước khi push lên DockerHub
RUN openresty -t

EXPOSE 80 443

CMD ["openresty", "-g", "daemon off;"]
