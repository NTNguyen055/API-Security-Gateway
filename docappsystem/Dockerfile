# =============================================================================
# Adaptive Web Security Gateway — Django App Dockerfile
# Multi-stage build: builder (compile wheels) → runtime (lean image)
# =============================================================================

# =============================================================================
# STAGE 1: Builder — compile Python wheels
# =============================================================================
FROM python:3.12-slim AS builder

WORKDIR /build

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_ROOT_USER_ACTION=ignore \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

# Build deps — chỉ cần ở stage này, không copy sang runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        python3-dev \
        default-libmysqlclient-dev \
        pkg-config \
        gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

# Build tất cả wheels vào /wheels — cache-friendly layer
RUN pip install --upgrade pip \
 && pip wheel --no-cache-dir --no-deps --wheel-dir /wheels -r requirements.txt


# =============================================================================
# STAGE 2: Runtime — lean image, không có build tools
# FIX: bỏ build-essential và libmariadb-dev khỏi runtime
#      chỉ cần libmariadb3 (shared library runtime)
# =============================================================================
FROM python:3.12-slim AS runtime

WORKDIR /app

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_ROOT_USER_ACTION=ignore \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONOPTIMIZE=1 \
    # Gunicorn tuning
    GUNICORN_WORKERS=2 \
    GUNICORN_THREADS=2 \
    GUNICORN_TIMEOUT=60

# FIX: chỉ cài runtime library, không cài -dev headers
# libmariadb3  : shared library để mysqlclient chạy
# curl         : dùng cho healthcheck (bỏ nếu chuyển sang python healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
        libmariadb3 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy wheels từ builder và install — không cần build tools
COPY --from=builder /wheels /wheels
COPY requirements.txt .

RUN pip install --no-index --no-cache-dir --find-links=/wheels -r requirements.txt \
 && rm -rf /wheels requirements.txt

# ── SECURITY: non-root user với UID cố định ──────────────────
# FIX: UID cố định 1001 để volume permissions nhất quán giữa các build
RUN groupadd -g 1001 appgroup \
 && useradd -u 1001 -g appgroup -m -s /bin/bash appuser

# ── COPY SOURCE CODE ──────────────────────────────────────────
# FIX: --chown đảm bảo appuser có quyền đọc ngay từ đầu
# (Cần có .dockerignore để tránh copy .env, __pycache__, .git)
COPY --chown=appuser:appgroup . .

# ── TẠO THƯ MỤC CẦN THIẾT ────────────────────────────────────
# static/ phải tồn tại để collectstatic trong settings.py không lỗi
RUN mkdir -p staticfiles media static \
 && chown -R appuser:appgroup staticfiles media static

# ── SWITCH TO NON-ROOT ────────────────────────────────────────
USER appuser

# ── EXPOSE ───────────────────────────────────────────────────
EXPOSE 8000

# ── HEALTHCHECK ──────────────────────────────────────────────
# FIX: dùng python thay vì curl — không cần install curl vào image
# docker-compose.yml cũng override healthcheck này, đồng bộ nhau
HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=40s \
    CMD python -c \
        "import urllib.request; \
         urllib.request.urlopen('http://localhost:8000/health/')" \
    || exit 1

# ── ENTRYPOINT / CMD ──────────────────────────────────────────
# FIX: CMD ở Dockerfile chỉ là fallback
# docker-compose.yml dùng `command:` để override → giữ nhất quán
# Đặt cùng params với docker-compose để không bị mismatch
CMD ["gunicorn", \
     "docappsystem.wsgi:application", \
     "--bind",                  "0.0.0.0:8000", \
     "--workers",               "2", \
     "--threads",               "2", \
     "--timeout",               "60", \
     "--max-requests",          "1000", \
     "--max-requests-jitter",   "100", \
     "--access-logfile",        "-", \
     "--error-logfile",         "-", \
     "--log-level",             "info"]
