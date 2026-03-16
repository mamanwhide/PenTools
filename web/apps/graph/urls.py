from django.urls import path
from . import views

app_name = "graph"

urlpatterns = [
    # Graph page
    path("<uuid:project_id>/", views.graph_page, name="project_graph"),
]
