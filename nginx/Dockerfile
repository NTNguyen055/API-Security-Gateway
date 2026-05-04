FROM openresty/openresty:alpine-fat

# ================= BASE =================
# Thêm libmaxminddb-dev để phục vụ quá trình build thư viện lua-resty-maxminddb
RUN apk add --no-cache \
    ca-certificates \
    libmaxminddb \
    libmaxminddb-dev \
    openssl \
    curl \
    && update-ca-certificates

# ================= LUA ROCKS (CÀI ĐẶT THƯ VIỆN LUA) =================
# FIX 1: Pin (cố định) phiên bản để tránh lỗi sập hệ thống khi thư viện ra bản mới
# Bổ sung luôn redis và maxminddb để phục vụ kiến trúc tối ưu mới nhất
RUN luarocks install lua-resty-jwt 0.2.3 \
    && luarocks install lua-resty-http 0.17.2 \
    && luarocks install lua-resty-redis 0.29 \
    && luarocks install lua-resty-maxminddb 1.1.1

# ================= DIR =================
RUN mkdir -p \
    /usr/local/openresty/nginx/lua \
    /usr/local/openresty/nginx/logs \
    /usr/local/openresty/lualib/resty \
    /etc/nginx/geoip \
    /etc/letsencrypt/live/dacn3.duckdns.org

# ================= DUMMY SSL =================
# FIX 2: Tăng hạn SSL giả lập lên 10 năm (3650 days) để phòng trường hợp Let's Encrypt lỗi
RUN openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout /etc/letsencrypt/live/dacn3.duckdns.org/privkey.pem \
    -out /etc/letsencrypt/live/dacn3.duckdns.org/fullchain.pem \
    -subj "/CN=dacn3.duckdns.org"

# ================= COPY VENDOR =================
COPY vendor/resty/ /usr/local/openresty/lualib/resty/
COPY vendor/prometheus*.lua /usr/local/openresty/lualib/

# ================= GEOIP =================
COPY GeoLite2-Country.mmdb /etc/nginx/geoip/

# ================= CONFIG =================
COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY lua/ /usr/local/openresty/nginx/lua/

# ================= PERMISSION =================
# FIX 3: Áp dụng nguyên tắc Đặc quyền tối thiểu (Least Privilege)
# Chỉ cấp quyền đọc (644) cho file và quyền thực thi (755) cho folder cụ thể
RUN chown -R root:root /usr/local/openresty/nginx/lua/ \
    && chown root:root /usr/local/openresty/nginx/conf/nginx.conf \
    && chmod 644 /usr/local/openresty/nginx/conf/nginx.conf \
    && find /usr/local/openresty/nginx/lua/ -type f -exec chmod 644 {} \; \
    && find /usr/local/openresty/nginx/lua/ -type d -exec chmod 755 {} \;

# ================= VERIFY =================
RUN /usr/local/openresty/bin/openresty -t

# ================= PORT =================
EXPOSE 80 443 9145

# ================= RUN =================
CMD ["openresty", "-g", "daemon off;"]