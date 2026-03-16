"""
REST API endpoints for module introspection.
All routes are prefixed with /api/v1/modules/ (see pentools/urls.py).
"""
from django.urls import path
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from apps.modules.engine import ModuleRegistry


@login_required
def api_module_list(request):
    registry = ModuleRegistry.instance()
    q = request.GET.get("q", "")
    category = request.GET.get("category", "")

    if q:
        modules = registry.search(q)
    elif category:
        modules = registry.by_category().get(category, [])
    else:
        modules = registry.all()

    data = [m.schema_to_dict() for m in modules]
    return JsonResponse({"count": len(data), "results": data})


@login_required
def api_module_detail(request, module_id):
    registry = ModuleRegistry.instance()
    module = registry.get(module_id)
    if module is None:
        return JsonResponse({"error": "Not found"}, status=404)
    return JsonResponse(module.schema_to_dict())


@login_required
def api_categories(request):
    registry = ModuleRegistry.instance()
    by_cat = registry.by_category()
    data = {cat: [m.id for m in mods] for cat, mods in by_cat.items()}
    return JsonResponse({"categories": data})


urlpatterns = [
    path("", api_module_list, name="api_module_list"),
    path("categories/", api_categories, name="api_categories"),
    path("<str:module_id>/", api_module_detail, name="api_module_detail"),
]
