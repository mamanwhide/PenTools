from django.urls import path
from . import views

app_name = "targets"

urlpatterns = [
    path("", views.project_list, name="project_list"),
    path("new/", views.project_create, name="project_create"),
    path("<uuid:pk>/", views.project_detail, name="project_detail"),
    path("<uuid:pk>/delete/", views.project_delete, name="project_delete"),
    path("<uuid:project_pk>/targets/new/", views.target_create, name="target_create"),
    path("targets/<uuid:pk>/delete/", views.target_delete, name="target_delete"),
]
