from django.urls import path
from . import views

urlpatterns = [
    path("", views.channel_list, name="channel_list"),
    path("create/", views.channel_create, name="channel_create"),
    path("<uuid:pk>/test/", views.channel_test, name="channel_test"),
    path("<uuid:pk>/toggle/", views.channel_toggle, name="channel_toggle"),
    path("<uuid:pk>/delete/", views.channel_delete, name="channel_delete"),
]
