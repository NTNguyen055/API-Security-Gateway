# =========================
# STAGE 1: Builder
# =========================
FROM python:3.12-slim AS builder

WORKDIR /app

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_ROOT_USER_ACTION=ignore \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

# 1. Tạo sẵn thư mục man1 để chặn cảnh báo của xz-utils
# 2. Gộp chung việc cài xz-utils vào đây để tối ưu cache layer
RUN mkdir -p /usr/share/man/man1 && \
    apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    python3-dev \
    default-libmysqlclient-dev \
    pkg-config \
    gcc \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --upgrade pip \
 && pip wheel --no-cache-dir --no-deps --wheel-dir /wheels -r requirements.txt


# =========================
# STAGE 2: Runtime
# =========================
FROM python:3.12-slim

WORKDIR /app

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_ROOT_USER_ACTION=ignore \
    PYTHONUNBUFFERED=1 \
    PYTHONOPTIMIZE=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DJANGO_SETTINGS_MODULE=docappsystem.settings

# Runtime deps nhẹ
RUN apt-get update && apt-get install -y --no-install-recommends \
    libmariadb3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy wheels
COPY --from=builder /wheels /wheels
COPY requirements.txt .

RUN pip install --no-cache-dir /wheels/* \
 && rm -rf /wheels

# Copy source
COPY . .

# =========================
# SECURITY
# =========================
RUN useradd -m -u 1001 appuser \
 && chown -R appuser:appuser /app

USER appuser

# =========================
# NETWORK
# =========================
EXPOSE 8000

# =========================
# HEALTHCHECK
# =========================
HEALTHCHECK --interval=30s --timeout=5s --retries=5 \
 CMD curl -fs http://localhost:8000/health/ || exit 1

# =========================
# GUNICORN (AUTO SCALE)
# =========================
CMD ["sh", "-c", "gunicorn docappsystem.wsgi:application \
    --bind 0.0.0.0:8000 \
    --workers $(nproc) \
    --threads 2 \
    --timeout 90 \
    --keep-alive 5 \
    --max-requests 1000 \
    --max-requests-jitter 100 \
    --preload"]