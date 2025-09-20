from django.http import JsonResponse
from rest_framework_simplejwt.tokens import UntypedToken
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from django.contrib.auth.models import AnonymousUser
from .models import CustomUser
import jwt
from django.conf import settings
from rest_framework_simplejwt.settings import api_settings


class JWTAuthenticationMiddleware:
    """
    Custom middleware to authenticate users using JWT tokens from cookies
    """
    
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Public routes: skip JWT parsing/auth
        path = getattr(request, 'path', '')
        if self._is_public_path(path):
            return self.get_response(request)

        # Get access token from cookies
        access_token = request.COOKIES.get('access')
        
        if access_token:
            try:
                # Validate the token
                UntypedToken(access_token)
                
                # Decode the token to get user information
                decoded_token = jwt.decode(
                    access_token, 
                    api_settings.SIGNING_KEY, 
                    algorithms=[api_settings.ALGORITHM]
                )
                
                user_id = decoded_token.get('user_id')
                
                if user_id:
                    try:
                        user = CustomUser.objects.get(id=user_id)
                        # Attach domain user; add a lightweight flag for checks in views
                        try:
                            setattr(user, 'is_authenticated', True)
                        except Exception:
                            pass
                        request.user = user
                    except CustomUser.DoesNotExist:
                        request.user = AnonymousUser()
                else:
                    request.user = AnonymousUser()
                    
            except (InvalidToken, TokenError, jwt.ExpiredSignatureError, jwt.InvalidTokenError):
                request.user = AnonymousUser()
        else:
            request.user = AnonymousUser()

        response = self.get_response(request)
        return response

    def _is_public_path(self, path: str) -> bool:
        if not path:
            return False
        # Support multiple versions/prefixes e.g., /api/, /v2/api/
        public_keywords = [
            '/signup',
            '/verify_otp',
            '/login',
            '/verify_login_otp',
            '/logout',  # allow logout without requiring existing auth state
        ]
        return any(kw in path for kw in public_keywords)


class RoleBasedAuthorizationMiddleware:
    """
    Middleware to handle role-based authorization
    """
    
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        return response

    @staticmethod
    def check_permission(user, required_roles):
        """
        Check if user has required role permissions
        """
        if not hasattr(user, 'role'):
            return False
        
        return user.role in required_roles

    @staticmethod
    def require_authentication(view_func):
        """
        Decorator to require authentication
        """
        def wrapper(request, *args, **kwargs):
            # DRF wraps the HttpRequest into rest_framework.request.Request
            # Always check request.user.is_authenticated for reliability
            user = getattr(request, 'user', None)
            is_auth = getattr(user, 'is_authenticated', False)
            if not is_auth:
                return JsonResponse(
                    {'error': 'Authentication required'},
                    status=401
                )
            return view_func(request, *args, **kwargs)
        return wrapper

    @staticmethod
    def require_roles(allowed_roles):
        """
        Decorator to require specific roles
        """
        def decorator(view_func):
            def wrapper(request, *args, **kwargs):
                user = getattr(request, 'user', None)
                is_auth = getattr(user, 'is_authenticated', False)
                if not is_auth:
                    return JsonResponse(
                        {'error': 'Authentication required'},
                        status=401
                    )

                if not RoleBasedAuthorizationMiddleware.check_permission(user, allowed_roles):
                    return JsonResponse(
                        {'error': 'Insufficient permissions'},
                        status=403
                    )
                
                return view_func(request, *args, **kwargs)
            return wrapper
        return decorator
