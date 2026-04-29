# =============================================================================
# Adaptive API Security Gateway — FINAL FIXED BUILD
# =============================================================================

FROM openresty/openresty:1.25.3.2-alpine-fat

# ================= BASE =================
RUN apk add --no-cache \
    curl \
    ca-certificates \
    openssl \
    openssl-dev \
 && update-ca-certificates

ENV LUA_PATH="/usr/local/openresty/lualib/?.lua;;"

# ================= DIR =================
RUN mkdir -p /usr/local/openresty/nginx/lua \
 && mkdir -p /usr/local/openresty/lualib/resty

# =============================================================================
# 🔒 INSTALL LUA MODULES (PRODUCTION-GRADE DETERMINISTIC BUILD)
# =============================================================================
RUN set -eux && \
# 1. lua-resty-http (v0.17.2)
curl -fL https://github.com/ledgetech/lua-resty-http/archive/refs/tags/v0.17.2.tar.gz | tar -xz && \
cp -r lua-resty-http-0.17.2/lib/resty/* /usr/local/openresty/lualib/resty/ && \
# 2. lua-resty-redis (v0.29)
curl -fL https://github.com/openresty/lua-resty-redis/archive/refs/tags/v0.29.tar.gz | tar -xz && \
cp -r lua-resty-redis-0.29/lib/resty/* /usr/local/openresty/lualib/resty/ && \
# 3. lua-resty-limit-traffic (v0.08)
curl -fL https://github.com/openresty/lua-resty-limit-traffic/archive/refs/tags/v0.08.tar.gz | tar -xz && \
cp -r lua-resty-limit-traffic-0.08/lib/resty/* /usr/local/openresty/lualib/resty/ && \
# 4. lua-resty-string (v0.15)
curl -fL https://github.com/openresty/lua-resty-string/archive/refs/tags/v0.15.tar.gz | tar -xz && \
cp -r lua-resty-string-0.15/lib/resty/* /usr/local/openresty/lualib/resty/ && \
# 5. lua-resty-jwt (Locked bằng commit hash ee1d024 - Bất biến vĩnh viễn)
curl -fL https://github.com/SkyLothar/lua-resty-jwt/archive/ee1d024.tar.gz | tar -xz && \
cp -r lua-resty-jwt-ee1d024*/lib/resty/* /usr/local/openresty/lualib/resty/ && \
# 6. lua-resty-hmac (Locked bằng commit hash 23da759 - Bất biến vĩnh viễn)
curl -fL https://github.com/jkeys089/lua-resty-hmac/archive/23da759.tar.gz | tar -xz && \
cp -r lua-resty-hmac-23da759*/lib/resty/* /usr/local/openresty/lualib/resty/ && \
# 7. lua-resty-openssl (1.7.1)
curl -fL https://github.com/fffonion/lua-resty-openssl/archive/refs/tags/1.7.1.tar.gz | tar -xz && \
cp -r lua-resty-openssl-1.7.1/lib/resty/* /usr/local/openresty/lualib/resty/ && \
# 8. nginx-lua-prometheus (0.20240525 - SỬ DỤNG *.lua ĐỂ COPY TOÀN BỘ)
curl -fL https://github.com/knyar/nginx-lua-prometheus/archive/refs/tags/0.20240525.tar.gz | tar -xz && \
cp nginx-lua-prometheus-*/*.lua /usr/local/openresty/lualib/ && \
# Cleanup
rm -rf lua-resty-* nginx-lua-prometheus-*

# =============================================================================
# 🧪 VERIFY
# =============================================================================
RUN /usr/local/openresty/bin/resty -e "\
require 'cjson'; \
require 'resty.redis'; \
require 'resty.http'; \
require 'resty.jwt'; \
require 'resty.hmac'; \
require 'resty.sha256'; \
require 'resty.limit.req'; \
require 'resty.openssl.x509.chain'; \
require 'prometheus'; \
print('ALL MODULES OK'); \
"

# =============================================================================
# CONFIG
# =============================================================================
COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY lua/       /usr/local/openresty/nginx/lua/

# =============================================================================
# PERMISSIONS
# =============================================================================
RUN chmod -R 755 /usr/local/openresty/lualib \
 && chmod -R 755 /usr/local/openresty/nginx/lua \
 && mkdir -p /usr/local/openresty/nginx/logs
    
# =============================================================================
# RUN
# =============================================================================
EXPOSE 80 443
CMD ["openresty", "-g", "daemon off;"]