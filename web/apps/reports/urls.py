from django.urls import path
from . import views

urlpatterns = [
    path("", views.report_list, name="report_list"),
    path("create/", views.report_create, name="report_create"),
    path("<uuid:pk>/", views.report_detail, name="report_detail"),
    path("<uuid:pk>/builder/", views.report_builder, name="report_builder"),
    path("<uuid:pk>/builder/save/", views.report_builder_save, name="report_builder_save"),
    path("<uuid:pk>/generate/", views.report_generate, name="report_generate"),
    path("<uuid:pk>/download/", views.report_download, name="report_download"),
    path("<uuid:pk>/risk-matrix/", views.report_risk_matrix, name="report_risk_matrix"),
]
