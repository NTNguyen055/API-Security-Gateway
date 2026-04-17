# ==========================================
# STAGE 1: Builder
# ==========================================
FROM python:3.12-slim AS builder

WORKDIR /app

# Cài dependencies để build psycopg2
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    python3-dev \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

# Upgrade pip
RUN pip install --upgrade pip

# Build wheels
RUN pip wheel --no-cache-dir --no-deps --wheel-dir /app/wheels -r requirements.txt


# ==========================================
# STAGE 2: Runtime
# ==========================================
FROM python:3.12-slim

WORKDIR /app

# Chỉ cần runtime lib (nhẹ hơn builder)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/wheels /wheels
COPY --from=builder /app/requirements.txt .

RUN pip install --no-cache-dir /wheels/*

COPY . .

EXPOSE 8000

CMD ["gunicorn", "docappsystem.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "3"]