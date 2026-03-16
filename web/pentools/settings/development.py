from .base import *  # noqa

DEBUG = True
ALLOWED_HOSTS = ["*"]

# Dev: show SQL queries
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "console": {"class": "logging.StreamHandler"},
    },
    "loggers": {
        "django": {"handlers": ["console"], "level": "INFO"},
        "apps": {"handlers": ["console"], "level": "DEBUG"},
        "celery": {"handlers": ["console"], "level": "DEBUG"},
    },
}

# Allow all origins in dev
CORS_ALLOW_ALL_ORIGINS = True
