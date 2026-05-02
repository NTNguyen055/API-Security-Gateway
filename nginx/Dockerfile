FROM openresty/openresty:alpine-fat

# ================= BASE =================
RUN apk add --no-cache \
    ca-certificates \
    curl \
    git \
    libmaxminddb \
    && update-ca-certificates

# ================= DIR =================
RUN mkdir -p /usr/local/openresty/nginx/lua \
    /usr/local/openresty/nginx/logs \
    /etc/nginx/geoip

# ================= LUA MODULES =================
RUN luarocks install lua-resty-jwt 0.2.3-0 \
 && luarocks install lua-resty-http 0.17.2-0 \
 && luarocks install lua-resty-string

# Prometheus
RUN git clone https://github.com/knyar/nginx-lua-prometheus.git /tmp/prometheus \
 && cp /tmp/prometheus/prometheus.lua /usr/local/openresty/lualib/ \
 && rm -rf /tmp/prometheus

# MaxMind
RUN git clone https://github.com/api7/lua-resty-maxminddb.git /tmp/maxmind \
 && cp -r /tmp/maxmind/lib/resty /usr/local/openresty/lualib/ \
 && rm -rf /tmp/maxmind

# ================= GEOIP =================
COPY GeoLite2-Country.mmdb /etc/nginx/geoip/GeoLite2-Country.mmdb

# ================= CONFIG =================
COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY lua/ /usr/local/openresty/nginx/lua/

# ================= VERIFY =================
RUN openresty -t
RUN resty -e "require 'cjson'; require 'resty.maxminddb'; require 'resty.jwt'; print('OK')"

# ================= PORT =================
EXPOSE 80 443 9145

CMD ["openresty", "-g", "daemon off;"]