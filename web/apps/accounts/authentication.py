from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from .models import User


class APIKeyAuthentication(BaseAuthentication):
    """Authenticate via X-API-Key header or api_key query parameter."""

    def authenticate(self, request):
        api_key = (
            request.META.get("HTTP_X_API_KEY")
            or request.query_params.get("api_key")
        )
        if not api_key:
            return None

        try:
            user = User.objects.get(api_key=api_key, is_active=True)
        except User.DoesNotExist:
            raise AuthenticationFailed("Invalid API key.")

        return (user, None)
