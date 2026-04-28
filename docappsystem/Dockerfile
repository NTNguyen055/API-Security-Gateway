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

# Runtime deps 
RUN apt-get update && apt-get install -y --no-install-recommends \
    libmariadb3 \
    libmariadb-dev \
    libmariadb-dev-compat \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /wheels /wheels
COPY requirements.txt .

RUN pip install --no-cache-dir /wheels/* \
 && rm -rf /wheels

COPY . .

# ================= STATIC =================
RUN python manage.py collectstatic --noinput || true

# ================= SECURITY =================
RUN useradd -m appuser
USER appuser

EXPOSE 8000

# ================= HEALTHCHECK =================
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD \
  curl -f http://localhost:8000/health/ || exit 1

# ================= GUNICORN (TUNED) =================
CMD ["gunicorn", "docappsystem.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "3", "--threads", "2", "--timeout", "90", "--preload", "--max-requests", "1000", "--max-requests-jitter", "100"]