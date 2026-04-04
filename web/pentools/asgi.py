import os
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
from channels.security.websocket import AllowedHostsOriginValidator

# MED-02: default to production; override with DJANGO_SETTINGS_MODULE=pentools.settings.development for local dev
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "pentools.settings.production")

# Initialize Django ASGI early to populate app registry
django_asgi_app = get_asgi_application()

from apps.scans import routing as scan_routing  # noqa: E402 (after Django init)
from apps.graph import routing as graph_routing  # noqa: E402

application = ProtocolTypeRouter(
    {
        "http": django_asgi_app,
        "websocket": AllowedHostsOriginValidator(
            AuthMiddlewareStack(
                URLRouter(
                    scan_routing.websocket_urlpatterns
                    + graph_routing.websocket_urlpatterns
                )
            )
        ),
    }
)
