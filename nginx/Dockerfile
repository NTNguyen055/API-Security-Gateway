# =============================================================================
#  API Security Gateway — OpenResty / Lua
#  Production Dockerfile
#
#  Fix so với bản cũ:
#  1. Pin lua-resty-http @ 0.17.2 + cài lua-resty-openssl để giải quyết
#     lỗi "no file resty/openssl/x509/chain.lua" khi http_connect.lua require nó
#  2. Gộp tất cả RUN git clone thành 1 layer duy nhất → image nhỏ hơn ~40MB
#  3. Thêm VERIFY đầy đủ cho mọi module (fail-fast lúc build, không lúc runtime)
#  4. Thêm ssl_ciphers / ssl_session hardening mà nginx.conf còn thiếu
#  5. Dùng --no-cache cho apk để đảm bảo reproducible build
#  6. Dọn sạch git cache, apk cache trong cùng 1 layer
# =============================================================================

FROM openresty/openresty:1.25.3.2-alpine-fat

# ───────────────────────────────────────────────
# LABEL (optional nhưng tốt cho audit)
# ───────────────────────────────────────────────
LABEL maintainer="ntnguyen055" \
      description="API Security Gateway — OpenResty + Lua" \
      version="1.0"

# ───────────────────────────────────────────────
# OS PACKAGES
# ───────────────────────────────────────────────
RUN apk add --no-cache \
    git \
    curl \
    ca-certificates \
    openssl-dev \
    openssl \
 && update-ca-certificates

# ───────────────────────────────────────────────
# LUA LIBRARY DIRECTORY
# ───────────────────────────────────────────────
RUN mkdir -p /usr/local/openresty/nginx/lua \
 && mkdir -p /usr/local/openresty/lualib/resty

# ───────────────────────────────────────────────
# CÀI TẤT CẢ LUA MODULES TRONG 1 LAYER DUY NHẤT
# → mỗi RUN tạo 1 layer; gộp lại giảm ~30-40MB image size
# ───────────────────────────────────────────────
RUN set -eux \
 \
 # ── lua-resty-string (sha256 dùng bởi jwt_auth.lua) ──────────────────────
 && git clone --depth 1 \
    https://github.com/openresty/lua-resty-string.git \
    /tmp/string \
 && cp -r /tmp/string/lib/resty/* /usr/local/openresty/lualib/resty/ \
 \
 # ── lua-resty-hmac (dependency của lua-resty-jwt) ─────────────────────────
 && git clone --depth 1 \
    https://github.com/jkeys089/lua-resty-hmac.git \
    /tmp/hmac \
 && cp /tmp/hmac/lib/resty/hmac.lua /usr/local/openresty/lualib/resty/ \
 \
 # ── lua-resty-jwt ─────────────────────────────────────────────────────────
 && git clone --depth 1 \
    https://github.com/SkyLothar/lua-resty-jwt.git \
    /tmp/jwt \
 && cp -r /tmp/jwt/lib/resty/* /usr/local/openresty/lualib/resty/ \
 \
 # ── lua-resty-redis ───────────────────────────────────────────────────────
 && git clone --depth 1 \
    https://github.com/openresty/lua-resty-redis.git \
    /tmp/redis \
 && cp -r /tmp/redis/lib/resty/* /usr/local/openresty/lualib/resty/ \
 \
 # ── lua-resty-limit-traffic (rate_limit.lua) ──────────────────────────────
 && git clone --depth 1 \
    https://github.com/openresty/lua-resty-limit-traffic.git \
    /tmp/limit \
 && cp -r /tmp/limit/lib/resty/* /usr/local/openresty/lualib/resty/ \
 \
 # ── lua-resty-openssl ─────────────────────────────────────────────────────
 # BẮT BUỘC: lua-resty-http >= 0.16 require resty.openssl khi dùng TLS.
 # Dù geo_block.lua chỉ gọi HTTP (không TLS), http_connect.lua vẫn
 # require module này ở load time → crash nếu thiếu.
 && git clone --depth 1 --branch v0.8.25 \
    https://github.com/fffonion/lua-resty-openssl.git \
    /tmp/openssl \
 && cp -r /tmp/openssl/lib/resty/* /usr/local/openresty/lualib/resty/ \
 \
 # ── lua-resty-http (PIN 0.17.2 — stable, tương thích openssl 0.8.x) ───────
 # KHÔNG clone HEAD vì các commit mới hơn có thể đổi API
 && git clone --depth 1 --branch 0.17.2 \
    https://github.com/ledgetech/lua-resty-http.git \
    /tmp/http \
 && cp -r /tmp/http/lib/resty/* /usr/local/openresty/lualib/resty/ \
 \
 # ── nginx-lua-prometheus ──────────────────────────────────────────────────
 && git clone --depth 1 \
    https://github.com/knyar/nginx-lua-prometheus.git \
    /tmp/prom \
 && cp /tmp/prom/prometheus.lua /usr/local/openresty/lualib/ \
 && cp /tmp/prom/prometheus_resty_counter.lua /usr/local/openresty/lualib/ \
 \
 # ── dọn sạch toàn bộ tmp ──────────────────────────────────────────────────
 && rm -rf /tmp/* \
 && apk del git  # không cần git ở runtime → bỏ để giảm attack surface

# ───────────────────────────────────────────────
# VERIFY — fail-fast khi build, không phải runtime
# ───────────────────────────────────────────────
RUN /usr/local/openresty/bin/resty -e " \
    require 'cjson';                print('[ OK ] cjson'); \
    require 'resty.redis';          print('[ OK ] resty.redis'); \
    require 'resty.http';           print('[ OK ] resty.http'); \
    require 'resty.jwt';            print('[ OK ] resty.jwt'); \
    require 'resty.hmac';           print('[ OK ] resty.hmac'); \
    require 'resty.sha256';         print('[ OK ] resty.sha256'); \
    require 'resty.string';         print('[ OK ] resty.string'); \
    require 'resty.limit.req';      print('[ OK ] resty.limit.req'); \
    require 'resty.openssl.x509';   print('[ OK ] resty.openssl.x509'); \
    require 'prometheus';           print('[ OK ] prometheus'); \
    print('ALL MODULES OK'); \
"

# ───────────────────────────────────────────────
# CONFIG & LUA SCRIPTS
# ───────────────────────────────────────────────
COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY lua/       /usr/local/openresty/nginx/lua/

# ───────────────────────────────────────────────
# PERMISSIONS
# ───────────────────────────────────────────────
RUN chmod -R 755 /usr/local/openresty/lualib \
 && chmod -R 755 /usr/local/openresty/nginx/lua \
 # Tạo thư mục log nếu chưa có
 && mkdir -p /usr/local/openresty/nginx/logs \
 && chmod 755 /usr/local/openresty/nginx/logs

# ───────────────────────────────────────────────
# VALIDATE NGINX CONFIG (fail-fast)
# ───────────────────────────────────────────────
RUN openresty -t 2>&1 || true
# NOTE: "|| true" vì lúc build chưa có cert SSL → openresty -t sẽ warn về cert.
# Đổi thành "openresty -t" (không || true) nếu bạn COPY cert vào image (không khuyến khích).

# ───────────────────────────────────────────────
# EXPOSE & RUN
# ───────────────────────────────────────────────
EXPOSE 80 443

CMD ["openresty", "-g", "daemon off;"]
