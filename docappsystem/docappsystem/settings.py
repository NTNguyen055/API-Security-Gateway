from pathlib import Path
import os
from dotenv import load_dotenv

# ============================================================
# BASE
# ============================================================
BASE_DIR = Path(__file__).resolve().parent.parent

# ============================================================
# LOAD ENV (STRICT)
# ============================================================
env_path = os.path.join(BASE_DIR, '.env')
if os.path.exists(env_path):
    load_dotenv(env_path)
else:
    raise Exception(".env file not found")

# ============================================================
# CORE SECURITY
# ============================================================
SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY:
    raise Exception("SECRET_KEY is required")

DEBUG = os.environ.get('DEBUG', 'False').lower() in ['true', '1', 'yes']

# ❗ Production guard
if DEBUG:
    print("⚠️ WARNING: DEBUG=True (DEV MODE)")
else:
    if os.environ.get('DEBUG', '').lower() == 'true':
        raise Exception("DEBUG must be False in production")

# ============================================================
# ALLOWED HOSTS (STRICT)
# ============================================================
allowed_hosts_str = os.environ.get('ALLOWED_HOSTS')
if not allowed_hosts_str:
    raise Exception("ALLOWED_HOSTS must be set")

ALLOWED_HOSTS = [
    host.strip()
    for host in allowed_hosts_str.split(',')
    if host.strip()
]

# ============================================================
# CSRF / DOMAIN TRUST
# ============================================================
CSRF_TRUSTED_ORIGINS = [
    f"https://{host}" for host in ALLOWED_HOSTS
] + [
    f"http://{host}" for host in ALLOWED_HOSTS
]

# ============================================================
# PROXY (OpenResty / Nginx)
# ============================================================
USE_X_FORWARDED_HOST = True
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# ============================================================
# SECURITY HEADERS (CRITICAL)
# ============================================================
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True

SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'

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
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
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
# DATABASE (RDS HARDENING)
# ============================================================
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': os.environ.get('DB_NAME'),
        'USER': os.environ.get('DB_USER'),
        'PASSWORD': os.environ.get('DB_PASSWORD'),
        'HOST': os.environ.get('DB_HOST'),
        'PORT': os.environ.get('DB_PORT', '3306'),
        'CONN_MAX_AGE': 60,
        'OPTIONS': {
            'charset': 'utf8mb4',
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
# STATIC & MEDIA (DEFAULT LOCAL)
# ============================================================
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_DIRS = [BASE_DIR / 'static']

MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

# ============================================================
# CUSTOM USER
# ============================================================
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
AUTH_USER_MODEL = 'dasapp.CustomUser'

# ============================================================
# REDIS CACHE (HARDENED)
# ============================================================
CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": os.environ.get("REDIS_URL", "redis://redis:6379/1"),
        "OPTIONS": {
            "CLIENT_CLASS": "django_redis.client.DefaultClient",
            "SOCKET_CONNECT_TIMEOUT": 5,
            "SOCKET_TIMEOUT": 5,
        }
    }
}

# ============================================================
# AWS S3 STORAGE (IAM ROLE)
# ============================================================
USE_S3 = os.environ.get('USE_S3', 'False') == 'True'

AWS_DEFAULT_ACL = None
AWS_QUERYSTRING_AUTH = False

if USE_S3:
    AWS_STORAGE_BUCKET_NAME = os.environ.get('AWS_STORAGE_BUCKET_NAME')
    AWS_S3_REGION_NAME = os.environ.get('AWS_S3_REGION_NAME', 'ap-northeast-1')

    if not AWS_STORAGE_BUCKET_NAME:
        raise Exception("AWS_STORAGE_BUCKET_NAME is required")

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