from django.urls import path
from . import views

app_name = "scans"

urlpatterns = [
    # Core scan CRUD
    path("", views.scan_list, name="list"),
    path("dashboard/", views.scan_dashboard, name="dashboard"),
    path("new/<str:module_id>/", views.scan_create, name="create"),
    path("<uuid:job_id>/", views.scan_detail, name="detail"),
    path("<uuid:job_id>/cancel/", views.scan_cancel, name="cancel"),
    path("<uuid:job_id>/retry/", views.scan_retry, name="retry"),

    # Scheduled scans
    path("schedules/", views.schedule_list, name="schedule_list"),
    path("schedules/new/<str:module_id>/", views.schedule_create, name="schedule_create"),
    path("schedules/<uuid:schedule_id>/toggle/", views.schedule_toggle, name="schedule_toggle"),
    path("schedules/<uuid:schedule_id>/delete/", views.schedule_delete, name="schedule_delete"),

    # Diff reports
    path("diffs/", views.diff_list, name="diff_list"),
    path("diffs/<uuid:diff_id>/", views.diff_detail, name="diff_detail"),

    # Scan chains
    path("chains/", views.chain_list, name="chain_list"),
    path("chains/new/", views.chain_create, name="chain_create"),
    path("chains/<uuid:chain_id>/toggle/", views.chain_toggle, name="chain_toggle"),
    path("chains/<uuid:chain_id>/delete/", views.chain_delete, name="chain_delete"),
]
