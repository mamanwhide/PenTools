"""
Context processor: injects module registry and user project list into every template context.
Add 'apps.modules.context_processors.module_registry' to TEMPLATES[0]['OPTIONS']['context_processors'].
"""
from apps.modules.engine import ModuleRegistry


def module_registry(request):
    registry = ModuleRegistry.instance()
    ctx = {
        "module_registry": registry,
        "module_categories": registry.by_category(),
        "module_category_list": registry.categories(),
    }
    if request.user.is_authenticated:
        from django.db.models import Q
        from apps.targets.models import Project
        ctx["user_all_projects"] = Project.objects.filter(
            Q(owner=request.user) | Q(members=request.user)
        ).distinct().order_by("name")
    else:
        ctx["user_all_projects"] = []
    return ctx
