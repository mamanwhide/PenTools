from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.http import require_POST

from .models import User


def login_view(request):
    if request.user.is_authenticated:
        return redirect("dashboard")

    if request.method == "POST":
        username = request.POST.get("username", "").strip()
        password = request.POST.get("password", "")

        # Prevent username enumeration: same error for both bad user and bad pass
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            next_url = request.GET.get("next", "/dashboard/")
            return redirect(next_url)
        else:
            messages.error(request, "Invalid credentials.")

    return render(request, "base/login.html")


@login_required
def logout_view(request):
    logout(request)
    return redirect("accounts:login")


@login_required
def profile_view(request):
    return render(request, "dashboard/profile.html", {"user": request.user})


@login_required
@require_POST
def regenerate_api_key(request):
    new_key = request.user.regenerate_api_key()
    return JsonResponse({"api_key": new_key})


def health_check(request):
    return JsonResponse({"status": "ok", "service": "pentools"})
