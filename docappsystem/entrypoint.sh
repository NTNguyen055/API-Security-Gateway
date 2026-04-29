#!/bin/sh

# Đảm bảo script dừng lại nếu có lỗi xảy ra
set -e

echo "=== [1/3] Running Database Migrations ==="
# Lệnh này sẽ tự động áp dụng các file migration mới nhất vào RDS
python manage.py migrate --noinput

echo "=== [2/3] Collecting Static Files ==="
# Đẩy 602+ file tĩnh lên S3 (Vì USE_S3=True và đã có IAM Role)
python manage.py collectstatic --noinput

echo "=== [3/3] Starting Gunicorn Server ==="
# Khởi động Gunicorn
exec gunicorn docappsystem.wsgi:application \
    --bind 0.0.0.0:8000 \
    --workers 3 \
    --threads 2 \
    --timeout 90 \
    --preload \
    --max-requests 1000 \
    --max-requests-jitter 100