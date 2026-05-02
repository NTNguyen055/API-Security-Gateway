FROM openresty/openresty:alpine-fat

# ================= BASE =================
RUN apk add --no-cache \
    ca-certificates \
    libmaxminddb \
    openssl \
    && update-ca-certificates
# (Thêm openssl vào lệnh apk add bên trên)

# ================= DIR =================
RUN mkdir -p \
    /usr/local/openresty/nginx/lua \
    /usr/local/openresty/nginx/logs \
    /usr/local/openresty/lualib/resty \
    /etc/nginx/geoip \
    /etc/letsencrypt/live/dacn3.duckdns.org
# (Thêm thư mục letsencrypt vào lệnh mkdir bên trên)

# ================= DUMMY SSL =================
# Tạo chứng chỉ giả để pass lệnh test config Nginx trong Jenkins.
# Khi deploy, volume của Docker sẽ đè chứng chỉ thật lên đường dẫn này.
RUN openssl req -x509 -nodes -days 1 -newkey rsa:2048 \
    -keyout /etc/letsencrypt/live/dacn3.duckdns.org/privkey.pem \
    -out /etc/letsencrypt/live/dacn3.duckdns.org/fullchain.pem \
    -subj "/CN=dacn3.duckdns.org"

# ================= COPY VENDOR =================
COPY vendor/resty/ /usr/local/openresty/lualib/resty/
COPY vendor/prometheus.lua /usr/local/openresty/lualib/

# ================= GEOIP =================
COPY GeoLite2-Country.mmdb /etc/nginx/geoip/

# ================= CONFIG =================
COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY lua/ /usr/local/openresty/nginx/lua/

# ================= PERMISSION =================
RUN chmod -R 755 /usr/local/openresty/

# ================= VERIFY =================
# Bây giờ bạn có thể tự tin bật lại lệnh này, Nginx sẽ không kêu ca lỗi host hay lỗi SSL nữa!
RUN /usr/local/openresty/bin/openresty -t

# ================= PORT =================
EXPOSE 80 443 9145

# ================= RUN =================
CMD ["openresty", "-g", "daemon off;"]