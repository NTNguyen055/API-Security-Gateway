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

RUN pip install --upgrade pip
RUN pip wheel --no-cache-dir --no-deps --wheel-dir /wheels -r requirements.txt

# =========================
# STAGE 2: Runtime
# =========================
FROM python:3.12-slim

WORKDIR /app

ENV DEBIAN_FRONTEND=noninteractive
ENV PIP_ROOT_USER_ACTION=ignore
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    default-libmysqlclient-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /wheels /wheels
COPY requirements.txt .

RUN pip install --no-cache-dir /wheels/*

COPY . .

EXPOSE 8000

CMD ["gunicorn", "docappsystem.wsgi:application", \
     "--bind", "0.0.0.0:8000", \
     "--workers", "2", \
     "--threads", "2", \
     "--timeout", "60"]