# =========================
# STAGE 1: Builder
# =========================
FROM python:3.12-slim AS builder

WORKDIR /app

ENV DEBIAN_FRONTEND=noninteractive
ENV PIP_ROOT_USER_ACTION=ignore

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    python3-dev \
    default-libmysqlclient-dev \
    pkg-config \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --upgrade pip \
 && pip wheel --no-cache-dir --no-deps --wheel-dir /wheels -r requirements.txt


# =========================
# STAGE 2: Runtime
# =========================
FROM python:3.12-slim

WORKDIR /app

ENV DEBIAN_FRONTEND=noninteractive
ENV PIP_ROOT_USER_ACTION=ignore
ENV PYTHONUNBUFFERED=1
ENV PYTHONOPTIMIZE=1

# Runtime deps (Cần curl cho Healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libmariadb-dev \
    libmariadb-dev-compat \
    curl \
 && rm -rf /var/lib/apt/lists/*

# Tạo user an toàn
RUN useradd -m appuser

# Tạo thư mục cho file tĩnh/media
RUN mkdir -p /app/staticfiles /app/media && chown -R appuser:appuser /app

COPY --from=builder /wheels /wheels
COPY requirements.txt .

RUN pip install --no-cache-dir /wheels/* \
 && rm -rf /wheels

# Copy toàn bộ code
COPY --chown=appuser:appuser . .

# [MỚI] Cấp quyền thực thi cho file entrypoint
RUN chmod +x /app/entrypoint.sh && chown appuser:appuser /app/entrypoint.sh

USER appuser

EXPOSE 8000

# Healthcheck tối ưu: 
# - Dùng 127.0.0.1 để tránh thử IPv6
# - start-period=30s để Django kịp chạy migrate/collectstatic
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 CMD \
  curl -f http://127.0.0.1:8000/health/ || exit 1
  
# [MỚI] Sử dụng ENTRYPOINT thay vì CMD
ENTRYPOINT ["/app/entrypoint.sh"]