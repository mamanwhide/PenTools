from django.urls import path
from . import views

app_name = "modules"

urlpatterns = [
    path("", views.module_list, name="list"),
    path("<str:module_id>/", views.module_detail, name="detail"),
]
