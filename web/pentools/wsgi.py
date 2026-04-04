import os
from django.core.wsgi import get_wsgi_application

# MED-02: default to production; set DJANGO_SETTINGS_MODULE=pentools.settings.development for local dev
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "pentools.settings.production")
application = get_wsgi_application()
