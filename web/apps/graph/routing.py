from django.urls import re_path
from . import consumers

websocket_urlpatterns = [
    re_path(r"ws/graph/(?P<project_id>[0-9a-f-]+)/$", consumers.GraphConsumer.as_asgi()),
]
