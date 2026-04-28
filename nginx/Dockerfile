# =============================================================================
# Adaptive API Security Gateway — FINAL PRO (STABLE BUILD)
# =============================================================================

FROM openresty/openresty:1.25.3.2-alpine-fat

LABEL maintainer="ntnguyen055" \
      description="Adaptive API Security Gateway (Final Stable)" \
      version="4.1"

# ================= BASE =================
RUN apk add --no-cache \
    curl \
    ca-certificates \
    openssl \
    opensssl-dev \
 && update-ca-certificates

ENV LUA_PATH="/usr/local/openresty/lualib/?.lua;;"

# ================= DIR =================
RUN mkdir -p /usr/local/openresty/nginx/lua \
 && mkdir -p /usr/local/openresty/lualib/resty

# =============================================================================
# 🔒 INSTALL LUA MODULES (STABLE + NO 404)
# =============================================================================
RUN set -eux && \

# -------- lua-resty-http --------
curl -fL https://github.com/ledgetech/lua-resty-http/archive/refs/tags/v0.17.2.tar.gz | tar -xz && \
cp lua-resty-http-0.17.2/lib/resty/http.lua /usr/local/openresty/lualib/resty/ && \

# -------- lua-resty-redis --------
curl -fL https://github.com/openresty/lua-resty-redis/archive/refs/tags/v0.29.tar.gz | tar -xz && \
cp lua-resty-redis-0.29/lib/resty/redis.lua /usr/local/openresty/lualib/resty/ && \

# -------- lua-resty-limit-traffic --------
curl -fL https://github.com/openresty/lua-resty-limit-traffic/archive/refs/tags/v0.07.tar.gz | tar -xz && \
cp -r lua-resty-limit-traffic-0.07/lib/resty/limit /usr/local/openresty/lualib/resty/ && \

# -------- lua-resty-string --------
curl -fL https://github.com/openresty/lua-resty-string/archive/refs/tags/v0.15.tar.gz | tar -xz && \
cp -r lua-resty-string-0.15/lib/resty/* /usr/local/openresty/lualib/resty/ && \

# -------- lua-resty-hmac (FIXED SOURCE) --------
curl -fL https://github.com/jprjr/lua-resty-hmac/archive/refs/heads/master.tar.gz | tar -xz && \
cp lua-resty-hmac-*/lib/resty/hmac.lua /usr/local/openresty/lualib/resty/ && \

# -------- lua-resty-jwt --------
curl -fL https://github.com/SkyLothar/lua-resty-jwt/archive/refs/tags/v0.2.3.tar.gz | tar -xz && \
cp -r lua-resty-jwt-0.2.3/lib/resty/* /usr/local/openresty/lualib/resty/ && \

# -------- lua-resty-openssl --------
curl -fL https://github.com/fffonion/lua-resty-openssl/archive/refs/tags/v1.4.0.tar.gz | tar -xz && \
cp -r lua-resty-openssl-1.4.0/lib/resty/* /usr/local/openresty/lualib/resty/ && \

# -------- prometheus --------
curl -fL https://github.com/knyar/nginx-lua-prometheus/archive/refs/tags/0.20240525.tar.gz | tar -xz && \
cp nginx-lua-prometheus-*/prometheus.lua /usr/local/openresty/lualib/ && \
cp nginx-lua-prometheus-*/prometheus_resty_counter.lua /usr/local/openresty/lualib/ && \

# -------- CLEAN --------
rm -rf /tmp/* lua-resty-* nginx-lua-prometheus-*

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
# VALIDATE
# =============================================================================
RUN openresty -t

# =============================================================================
# RUN
# =============================================================================
EXPOSE 80 443
CMD ["openresty", "-g", "daemon off;"]