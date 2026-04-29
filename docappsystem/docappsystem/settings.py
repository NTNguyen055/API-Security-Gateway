from pathlib import Path
import os
from dotenv import load_dotenv

# ============================================================
# BASE
# ============================================================
BASE_DIR = Path(__file__).resolve().parent.parent

# ============================================================
# LOAD ENV (DOCKER FIRST)
# ============================================================
if os.getenv("USE_DOTENV", "False") == "True":
    env_path = BASE_DIR / ".env"
    if env_path.exists():
        load_dotenv(env_path)


def get_env(name, default=None, required=False):
    val = os.getenv(name, default)
    if required and not val:
        raise Exception(f"{name} is required")
    return val


# ============================================================
# CORE SECURITY
# ============================================================
SECRET_KEY = get_env("SECRET_KEY", required=True)

DEBUG = get_env("DEBUG", "False").lower() in ["true", "1", "yes"]

if DEBUG:
    import warnings
    warnings.warn("DEBUG=True is enabled (DEV MODE)")
else:
    if get_env("DEBUG", "").lower() == "true":
        raise Exception("DEBUG must be False in production")


# ============================================================
# ALLOWED HOSTS (STRICT)
# ============================================================
allowed_hosts_str = get_env("ALLOWED_HOSTS", required=True)

ALLOWED_HOSTS = [
    host.strip()
    for host in allowed_hosts_str.split(",")
    if host.strip()
]

# ============================================================
# CSRF / DOMAIN TRUST
# ============================================================
CSRF_TRUSTED_ORIGINS = (
    [f"https://{host}" for host in ALLOWED_HOSTS] +
    [f"http://{host}" for host in ALLOWED_HOSTS]
)

CSRF_COOKIE_SECURE = True
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = "Lax"

# ============================================================
# SESSION SECURITY
# ============================================================
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_AGE = 3600
SESSION_SAVE_EVERY_REQUEST = True

# ============================================================
# PROXY (OPENRESTY)
# ============================================================
USE_X_FORWARDED_HOST = True
USE_X_FORWARDED_PORT = True

SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# ============================================================
# SECURITY HEADERS
# ============================================================
SECURE_SSL_REDIRECT = get_env("SECURE_SSL_REDIRECT", "False").lower() == "true"

SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "strict-origin-when-cross-origin"

X_FRAME_OPTIONS = "DENY"

# ============================================================
# APPLICATION
# ============================================================
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'dasapp',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',

    # CSRF vẫn giữ (Gateway không thay thế cái này)
    'django.middleware.csrf.CsrfViewMiddleware',

    'django.contrib.auth.middleware.AuthenticationMiddleware',
    
    # [FIX] Thêm Middleware đồng bộ Gateway ngay sau Authentication mặc định
    'docappsystem.middleware.GatewayIntegrationMiddleware',

    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'docappsystem.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'docappsystem.wsgi.application'

# ============================================================
# DATABASE (RDS HARDENED)
# ============================================================
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': get_env('DB_NAME', required=True),
        'USER': get_env('DB_USER', required=True),
        'PASSWORD': get_env('DB_PASSWORD', required=True),
        'HOST': get_env('DB_HOST', required=True),
        'PORT': get_env('DB_PORT', '3306'),
        'CONN_MAX_AGE': 60,
        'OPTIONS': {
            'charset': 'utf8mb4',
            'connect_timeout': 5,
        }
    }
}

# ============================================================
# PASSWORD VALIDATION
# ============================================================
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# ============================================================
# INTERNATIONALIZATION
# ============================================================
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'Asia/Ho_Chi_Minh'
USE_I18N = True
USE_TZ = True

# ============================================================
# STATIC & MEDIA (BASE PATHS)
# ============================================================
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_DIRS = [BASE_DIR / 'static']
MEDIA_ROOT = BASE_DIR / 'media'

# ============================================================
# CUSTOM USER
# ============================================================
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
AUTH_USER_MODEL = 'dasapp.CustomUser'

# ============================================================
# REDIS CACHE (STABLE)
# ============================================================
CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": get_env("REDIS_URL", "redis://redis:6379/1"),
        "OPTIONS": {
            "CLIENT_CLASS": "django_redis.client.DefaultClient",
            "SOCKET_CONNECT_TIMEOUT": 5,
            "SOCKET_TIMEOUT": 5,
            "RETRY_ON_TIMEOUT": True,
        }
    }
}

# ============================================================
# AWS S3 (OPTIONAL) & STORAGE BACKENDS
# ============================================================
USE_S3 = get_env('USE_S3', 'False') == 'True'

if USE_S3:
    AWS_STORAGE_BUCKET_NAME = get_env('AWS_STORAGE_BUCKET_NAME', required=True)
    AWS_S3_REGION_NAME = get_env('AWS_S3_REGION_NAME', 'ap-northeast-1')

    AWS_DEFAULT_ACL = None
    AWS_QUERYSTRING_AUTH = False

    AWS_S3_CUSTOM_DOMAIN = f'{AWS_STORAGE_BUCKET_NAME}.s3.{AWS_S3_REGION_NAME}.amazonaws.com'

    AWS_S3_FILE_OVERWRITE = False
    AWS_S3_OBJECT_PARAMETERS = {
        'CacheControl': 'max-age=86400',
    }

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

    STATIC_URL = f'https://{AWS_S3_CUSTOM_DOMAIN}/static/'
    MEDIA_URL = f'https://{AWS_S3_CUSTOM_DOMAIN}/media/'
else:
    # Chuẩn mới của Django 4.2+ khi không dùng S3 (Lưu local)
    STORAGES = {
        "default": {
            "BACKEND": "django.core.files.storage.FileSystemStorage",
        },
        "staticfiles": {
            "BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage",
        },
    }
    
    STATIC_URL = '/static/'
    MEDIA_URL = '/media/'

# ============================================================
# LOGGING (CRITICAL FOR DEBUG)
# ============================================================
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'simple': {
            'format': '[%(asctime)s] %(levelname)s %(message)s',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO',
    },
}