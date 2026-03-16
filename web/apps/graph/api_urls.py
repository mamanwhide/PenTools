from django.urls import path
from apps.graph import views as graph_views

urlpatterns = [
    path("<uuid:project_id>/", graph_views.graph_data_api, name="graph_data"),
    path("<uuid:project_id>/finding/<uuid:finding_id>/update/", graph_views.finding_update_api, name="finding_update"),
    path("<uuid:project_id>/findings/csv/", graph_views.findings_csv_api, name="findings_csv"),
    path("<uuid:project_id>/export/", graph_views.graph_json_export, name="graph_export"),
]
