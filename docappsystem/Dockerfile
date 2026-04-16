# ==========================================
# STAGE 1: Builder
# ==========================================
FROM python:3.12-slim AS builder

WORKDIR /app

# Bổ sung python3-dev để cung cấp đầy đủ C-headers cho mysqlclient
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    python3-dev \
    default-libmysqlclient-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

# Nâng cấp pip trước khi build wheel để tránh lỗi tương thích
RUN pip install --upgrade pip
RUN pip wheel --no-cache-dir --no-deps --wheel-dir /app/wheels -r requirements.txt

# ==========================================
# STAGE 2: Runtime
# ==========================================
FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    default-libmysqlclient-dev \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/wheels /wheels
COPY --from=builder /app/requirements.txt .

RUN pip install --no-cache /wheels/*

COPY . .

EXPOSE 8000

CMD ["gunicorn", "docappsystem.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "3"]