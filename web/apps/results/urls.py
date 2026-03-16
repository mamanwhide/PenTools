from django.urls import path
from . import views

urlpatterns = [
    path("", views.finding_list, name="finding_list"),
    path("create/", views.finding_create, name="finding_create"),
    path("<uuid:pk>/", views.finding_detail, name="finding_detail"),
    path("<uuid:pk>/edit/", views.finding_edit, name="finding_edit"),
    path("<uuid:pk>/status/", views.finding_update_status, name="finding_update_status"),
    path("check-duplicate/", views.finding_check_duplicate, name="finding_check_duplicate"),
    path("cvss-calculator/", views.cvss_calculator, name="cvss_calculator"),
]
