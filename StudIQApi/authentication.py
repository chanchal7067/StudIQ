from typing import Optional, Tuple
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import UntypedToken
from rest_framework_simplejwt.exceptions import InvalidToken, AuthenticationFailed
from django.contrib.auth.models import AnonymousUser
from .models import CustomUser


class CookieJWTAuthentication(JWTAuthentication):
    """
    DRF authentication class that authenticates using JWT access token stored in cookies.
    Returns your domain CustomUser instance so request.user works in views.
    """

    def authenticate(self, request) -> Optional[Tuple[CustomUser, UntypedToken]]:
        # Try to get token from cookies first
        raw_token = request.COOKIES.get('access')
        if not raw_token:
            return None

        try:
            validated_token = self.get_validated_token(raw_token)
        except InvalidToken:
            # If token is invalid/expired, do not block the request here.
            # Return None so public routes continue to work.
            return None

        user = self.get_user_from_token(validated_token)
        if user is None:
            # No user associated with token
            return (AnonymousUser(), None)

        # Mark authenticated for DRF checks
        try:
            setattr(user, 'is_authenticated', True)
        except Exception:
            pass

        return (user, validated_token)

    def get_user_from_token(self, validated_token) -> Optional[CustomUser]:
        # SimpleJWT uses 'user_id' claim by default
        user_id = validated_token.get('user_id', None)
        if user_id is None:
            return None
        try:
            return CustomUser.objects.get(id=user_id)
        except CustomUser.DoesNotExist:
            return None
