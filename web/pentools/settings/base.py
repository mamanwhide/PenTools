"""
PenTools — Django Settings Base
All environments inherit from this.
"""
import os
from pathlib import Path
from decouple import config

BASE_DIR = Path(__file__).resolve().parent.parent.parent

SECRET_KEY = config("DJANGO_SECRET_KEY")
DEBUG = config("DJANGO_DEBUG", default=False, cast=bool)
ALLOWED_HOSTS = config("DJANGO_ALLOWED_HOSTS", default="localhost").split(",")

# Trust all ALLOWED_HOSTS for CSRF. Explicit override via CSRF_TRUSTED_ORIGINS env var.
_csrf_origins_env = config("CSRF_TRUSTED_ORIGINS", default="")
if _csrf_origins_env:
    CSRF_TRUSTED_ORIGINS = [o.strip() for o in _csrf_origins_env.split(",")]
else:
    CSRF_TRUSTED_ORIGINS = [
        f"https://{host}" for host in ALLOWED_HOSTS if host not in ("*",)
    ] + [
        f"http://{host}" for host in ALLOWED_HOSTS if host not in ("*",)
    ]

# ─── Applications ────────────────────────────────────────────────────────
DJANGO_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
]

THIRD_PARTY_APPS = [
    "rest_framework",
    "corsheaders",
    "channels",
    "django_extensions",
    "django_celery_beat",
    "django_celery_results",
    "widget_tweaks",
]

LOCAL_APPS = [
    "apps.accounts",
    "apps.targets",
    "apps.scans",
    "apps.modules",
    "apps.results",
    # Attack category apps
    "apps.recon",
    "apps.injection",
    "apps.xss_modules",
    "apps.server_side",
    "apps.access_control",
    "apps.auth_attacks",
    "apps.client_side",
    "apps.api_audit",
    "apps.business_logic",
    "apps.http_attacks",
    "apps.disclosure",
    "apps.cloud",
    "apps.vuln_scan",
    "apps.static_tools",
    # Platform
    "apps.reports",
    "apps.notifications",
    "apps.graph",
]

INSTALLED_APPS = DJANGO_APPS + THIRD_PARTY_APPS + LOCAL_APPS

# ─── Middleware ──────────────────────────────────────────────────────────
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "pentools.urls"

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
                "apps.modules.context_processors.module_registry",
            ],
        },
    },
]

WSGI_APPLICATION = "pentools.wsgi.application"
ASGI_APPLICATION = "pentools.asgi.application"

# ─── Database ────────────────────────────────────────────────────────────
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": config("POSTGRES_DB", default="pentools"),
        "USER": config("POSTGRES_USER", default="pentools"),
        "PASSWORD": config("POSTGRES_PASSWORD"),
        "HOST": config("POSTGRES_HOST", default="db"),
        "PORT": config("POSTGRES_PORT", default="5432"),
        "CONN_MAX_AGE": 60,
    }
}

# ─── Caching / Redis ─────────────────────────────────────────────────────
REDIS_URL = config("REDIS_URL", default="redis://redis:6379/0")

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.redis.RedisCache",
        "LOCATION": REDIS_URL,
    }
}

# ─── Django Channels ─────────────────────────────────────────────────────
CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {
            "hosts": [REDIS_URL],
            "capacity": 1500,
            "expiry": 10,
        },
    }
}

# ─── Celery ──────────────────────────────────────────────────────────────
CELERY_BROKER_URL = config("CELERY_BROKER_URL", default="redis://redis:6379/0")
CELERY_RESULT_BACKEND = config("CELERY_RESULT_BACKEND", default="redis://redis:6379/1")
CELERY_ACCEPT_CONTENT = ["json"]
CELERY_TASK_SERIALIZER = "json"
CELERY_RESULT_SERIALIZER = "json"
CELERY_TIMEZONE = "UTC"
CELERY_TASK_TRACK_STARTED = True
CELERY_TASK_TIME_LIMIT = 7200          # 2 hours hard limit
CELERY_TASK_SOFT_TIME_LIMIT = 6900     # 1h55m soft limit (sends exception)
CELERY_WORKER_MAX_TASKS_PER_CHILD = 4  # Prevent memory leaks

CELERY_TASK_QUEUES_MAX_PRIORITY = 10
CELERY_TASK_DEFAULT_PRIORITY = 5

# Queue routing
CELERY_TASK_ROUTES = {
    "apps.scans.tasks.*":          {"queue": "scan_orchestration"},
    "apps.recon.tasks.*":          {"queue": "recon_queue"},
    "apps.injection.tasks.*":      {"queue": "injection_queue"},
    "apps.xss_modules.tasks.*":    {"queue": "xss_queue"},
    "apps.server_side.tasks.*":    {"queue": "server_audit_queue"},
    "apps.access_control.tasks.*": {"queue": "web_audit_queue"},
    "apps.auth_attacks.tasks.*":   {"queue": "auth_queue"},
    "apps.api_audit.tasks.*":      {"queue": "api_queue"},
    "apps.business_logic.tasks.*": {"queue": "business_logic_queue"},
    "apps.http_attacks.tasks.*":   {"queue": "http_queue"},
    "apps.client_side.tasks.*":    {"queue": "web_audit_queue"},
    "apps.disclosure.tasks.*":     {"queue": "recon_queue"},
    "apps.cloud.tasks.*":          {"queue": "recon_queue"},
    "apps.vuln_scan.tasks.*":      {"queue": "server_audit_queue"},
    "apps.reports.tasks.*":        {"queue": "report_queue"},
    "apps.notifications.tasks.*":  {"queue": "notification_queue"},
}

# ─── REST Framework ──────────────────────────────────────────────────────
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.SessionAuthentication",
        "apps.accounts.authentication.APIKeyAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 50,
    "DEFAULT_THROTTLE_CLASSES": [
        "rest_framework.throttling.UserRateThrottle",
    ],
    "DEFAULT_THROTTLE_RATES": {
        "user": "120/min",
        "anon": "10/min",
    },
}

# ─── Auth ─────────────────────────────────────────────────────────────────
AUTH_USER_MODEL = "accounts.User"
LOGIN_URL = "/login/"
LOGIN_REDIRECT_URL = "/dashboard/"
LOGOUT_REDIRECT_URL = "/login/"

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
     "OPTIONS": {"min_length": 12}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# ─── Static & Media ──────────────────────────────────────────────────────
STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "static"]

MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

# ─── Security ────────────────────────────────────────────────────────────
X_FRAME_OPTIONS = "DENY"
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_BROWSER_XSS_FILTER = True

# Field encryption key (for sensitive scan params)
FIELD_ENCRYPTION_KEY = config("FIELD_ENCRYPTION_KEY", default="")

# ─── Paths ───────────────────────────────────────────────────────────────
TOOLS_BIN_DIR = "/opt/tools/bin"
SCAN_OUTPUT_DIR = "/tmp/pentools"
WORDLISTS_DIR = BASE_DIR / "wordlists"

# ─── i18n ────────────────────────────────────────────────────────────────
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# ─── Notifications ───────────────────────────────────────────────────────
NOTIFICATION_TELEGRAM_DEFAULT_TOKEN = config("TELEGRAM_BOT_TOKEN", default="")
NOTIFICATION_SLACK_DEFAULT_WEBHOOK  = config("SLACK_WEBHOOK_URL",  default="")

# ─── Reports ─────────────────────────────────────────────────────────────
REPORTS_MEDIA_DIR = MEDIA_ROOT / "reports"
