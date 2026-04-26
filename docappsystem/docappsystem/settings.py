from pathlib import Path
import os
from dotenv import load_dotenv

# ================= BASE =================
BASE_DIR = Path(__file__).resolve().parent.parent

# ================= LOAD ENV =================
env_path = BASE_DIR / ".env"
if env_path.exists():
    load_dotenv(env_path)

# ================= CORE =================
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    raise Exception("SECRET_KEY is required")

DEBUG = os.environ.get("DEBUG", "False").lower() in ["true", "1", "yes"]

# ================= ALLOWED HOSTS =================
allowed_hosts_str = os.environ.get("ALLOWED_HOSTS", "")

ALLOWED_HOSTS = [
    h.strip() for h in allowed_hosts_str.split(",") if h.strip()
]

if not ALLOWED_HOSTS:
    if DEBUG:
        ALLOWED_HOSTS = ["*"]
    else:
        raise Exception("ALLOWED_HOSTS must be set in production")

# ================= CSRF =================
csrf_origins = os.environ.get("CSRF_TRUSTED_ORIGINS", "")
CSRF_TRUSTED_ORIGINS = [
    o.strip() for o in csrf_origins.split(",") if o.strip()
]

# ================= PROXY (OpenResty) =================
USE_X_FORWARDED_HOST = True
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# ================= SECURITY HARDENING =================
SECURE_SSL_REDIRECT = not DEBUG

SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True

SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = True

SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True

X_FRAME_OPTIONS = "DENY"

SECURE_HSTS_SECONDS = 31536000 if not DEBUG else 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# ================= APPLICATION =================
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "dasapp",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "docappsystem.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    }
]

WSGI_APPLICATION = "docappsystem.wsgi.application"

# ================= DATABASE =================
# FIX: đọc ENGINE từ env thay vì hardcode mysql.
# Cho phép Jenkinsfile truyền DB_ENGINE=django.db.backends.sqlite3
# khi chạy test mà không cần DB thật.
DATABASES = {
    "default": {
        "ENGINE": os.environ.get("DB_ENGINE", "django.db.backends.mysql"),
        "NAME": os.environ.get("DB_NAME"),
        "USER": os.environ.get("DB_USER"),
        "PASSWORD": os.environ.get("DB_PASSWORD"),
        "HOST": os.environ.get("DB_HOST"),
        "PORT": os.environ.get("DB_PORT", "3306"),
        "CONN_MAX_AGE": 60,
        "OPTIONS": {
            "connect_timeout": 5,
        },
    }
}

# ================= AUTH =================
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

AUTH_USER_MODEL = "dasapp.CustomUser"

# ================= I18N =================
LANGUAGE_CODE = "en-us"
TIME_ZONE = "Asia/Ho_Chi_Minh"
USE_I18N = True
USE_TZ = True

# ================= STATIC / MEDIA =================
STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"

# FIX: guard tránh warning khi thư mục static/ chưa tồn tại trong container
_static_dir = BASE_DIR / "static"
STATICFILES_DIRS = [_static_dir] if _static_dir.exists() else []

MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

# ================= REDIS CACHE =================
CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": os.environ.get("REDIS_URL", "redis://redis:6379/1"),
        "OPTIONS": {
            "CLIENT_CLASS": "django_redis.client.DefaultClient",
            "SOCKET_CONNECT_TIMEOUT": 3,
            "SOCKET_TIMEOUT": 3,
            "IGNORE_EXCEPTIONS": True,  # fail-open
        },
    }
}

# ================= S3 STORAGE =================
USE_S3 = os.environ.get("USE_S3", "False") == "True"

AWS_DEFAULT_ACL = None
AWS_QUERYSTRING_AUTH = False

if USE_S3:
    AWS_STORAGE_BUCKET_NAME = os.environ.get("AWS_STORAGE_BUCKET_NAME")
    AWS_S3_REGION_NAME = os.environ.get("AWS_S3_REGION_NAME", "ap-northeast-1")

    AWS_S3_CUSTOM_DOMAIN = (
        f"{AWS_STORAGE_BUCKET_NAME}.s3.{AWS_S3_REGION_NAME}.amazonaws.com"
    )

    STORAGES = {
        "default": {
            "BACKEND": "storages.backends.s3boto3.S3Boto3Storage",
            "OPTIONS": {"location": "media"},
        },
        "staticfiles": {
            "BACKEND": "storages.backends.s3boto3.S3StaticStorage",
            "OPTIONS": {"location": "static"},
        },
    }

    STATIC_URL = f"https://{AWS_S3_CUSTOM_DOMAIN}/static/"
    MEDIA_URL = f"https://{AWS_S3_CUSTOM_DOMAIN}/media/"

# ================= DEFAULT PK =================
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
