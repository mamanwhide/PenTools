from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.contrib import messages
from django.http import JsonResponse
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_POST
from django.core.cache import cache

from .models import User

# MED-08: brute-force constants (cache key: login_fail:<ip>)
_LOGIN_MAX_ATTEMPTS = 10    # lockout after N failures
_LOGIN_LOCKOUT_SEC  = 600   # 10-minute window


@never_cache
def login_view(request):
    if request.user.is_authenticated:
        return redirect("dashboard")

    if request.method == "POST":
        username = request.POST.get("username", "").strip()
        password = request.POST.get("password", "")

        # MED-08: rate-limit by IP to prevent password spray
        ip = request.META.get("HTTP_X_FORWARDED_FOR", request.META.get("REMOTE_ADDR", "unknown")).split(",")[0].strip()
        cache_key = f"login_fail:{ip}"
        failures = cache.get(cache_key, 0)
        if failures >= _LOGIN_MAX_ATTEMPTS:
            messages.error(request, "Too many failed login attempts. Please try again later.")
            return render(request, "base/login.html", status=429)

        # Prevent username enumeration: same error for both bad user and bad pass
        user = authenticate(request, username=username, password=password)
        if user is not None:
            cache.delete(cache_key)  # MED-08: reset counter on successful login
            login(request, user)
            next_url = request.GET.get("next", "/dashboard/")
            # HIGH-01: validate redirect URL to prevent open-redirect phishing
            if not url_has_allowed_host_and_scheme(
                next_url,
                allowed_hosts={request.get_host()},
                require_https=request.is_secure(),
            ):
                next_url = "/dashboard/"
            return redirect(next_url)
        else:
            # MED-08: increment failure counter
            cache.set(cache_key, failures + 1, _LOGIN_LOCKOUT_SEC)
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
