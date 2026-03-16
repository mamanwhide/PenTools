from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from apps.modules.engine import ModuleRegistry


@login_required
def module_list(request):
    registry = ModuleRegistry.instance()
    q = request.GET.get("q", "").strip()
    category = request.GET.get("category", "").strip()

    if q:
        modules = registry.search(q)
    elif category:
        modules = registry.by_category(category)
    else:
        modules = registry.all()

    categories = registry.categories()  # list of {slug, label, count}

    return render(request, "modules/list.html", {
        "modules": modules,
        "categories": categories,
        "active_category": category,
        "search_query": q,
        "total_modules": len(registry.all()),
    })


@login_required
def module_detail(request, module_id):
    registry = ModuleRegistry.instance()
    module = registry.get(module_id)
    if module is None:
        from django.http import Http404
        raise Http404(f"Module '{module_id}' not found.")

    schema = module.schema_to_dict()

    return render(request, "modules/detail.html", {
        "module": module,
        "schema": schema,
        "schema_json": __import__("json").dumps(schema),
    })
