from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from .serializers import SignupSerializer,VerifyOtpSerializer,LoginSerializer,VerifyLoginOtpSerializer, CompleteProfileSerializer, UserListSerializer, CurrentUserSerializer
from .middleware import RoleBasedAuthorizationMiddleware
from django.http import JsonResponse
from rest_framework_simplejwt.tokens import RefreshToken
import random
from .models import CustomUser, OTPTable

from django.views.decorators.csrf import csrf_exempt


@api_view(['POST'])
@permission_classes([AllowAny])
@csrf_exempt
def signup(request):
    serializer = SignupSerializer(data = request.data)
    if serializer.is_valid():
        user, otp = serializer.save()
        OTPTable.objects.create(
            user_id = user.id,
            mobile = user.mobile,
            otp = otp

        )
        return Response({"message" : "Signup Successfull Otp sent to your mobile", "user_id" : user.id, "mobile" : user.mobile, "otp" : otp}, status = status.HTTP_201_CREATED)
    return Response(serializer.errors, status = status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny])
@csrf_exempt
def verify_otp(request):
    serializer = VerifyOtpSerializer(data = request.data)
    if serializer.is_valid():
        return Response({"Message" :"otp verified successfully, you can now log in"}, status = status.HTTP_200_OK)
    return Response(serializer.errors, status = status.HTTP_400_BAD_REQUEST)

def set_tokens_as_cookies(response, user):
    # Use SimpleJWT to create tokens bound to the user, then add extra claims
    refresh = RefreshToken.for_user(user)
    # add custom claims for convenience (not required for auth)
    refresh['username'] = user.username
    refresh['role'] = user.role

    access_token = str(refresh.access_token)
    refresh_token = str(refresh)

    response.set_cookie(
        key = "access",
        value = access_token,
        httponly = True,
        secure = False,
        samesite = "Strict",

    )

    response.set_cookie(
        key = "refresh",
        value = refresh_token,
        httponly = True,
        secure = False,
        samesite = "Strict",

    )

    return response


@api_view(['POST'])
@permission_classes([AllowAny])
@csrf_exempt
def login(request):
    serializer = LoginSerializer(data = request.data)
    if serializer.is_valid():
        user = serializer.validated_data["user"]
        otp = str(random.randint(100000,999999))
        OTPTable.objects.create(
            user_id = user.id,
            mobile = user.mobile,
            otp = otp
        )
        print("Login OTP:", otp)

        return Response({"Message" : "Otp sent to your mobile"}, status = status.HTTP_200_OK)
    
    return Response(serializer.errors, status = status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny])
@csrf_exempt
def verify_login_otp(request):
    serializer = VerifyLoginOtpSerializer(data = request.data)
    if serializer.is_valid():
        user = serializer.validated_data["user"]
        response = Response({"Message" : "Login Successful"}, status = status.HTTP_200_OK)
        return set_tokens_as_cookies(response, user)
    
    return Response(serializer.errors, status = status.HTTP_400_BAD_REQUEST)
    
@api_view(['GET','PUT'])
def get_complete_profile_view_byid(request, user_id):
    try:
        user = CustomUser.objects.get(id = user_id)
    except CustomUser.DoesNotExist:
        return Response({"Error" : "User Not found"}, status = status.HTTP_404_NOT_FOUND)
    

    if request.method == "GET":
        serializer = CompleteProfileSerializer(user)
        return Response(serializer.data, status = status.HTTP_200_OK)
    
    elif request.method == "PUT":
        serializer = CompleteProfileSerializer(user, data = request.data, partial = True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status = status.HTTP_200_OK)
        return Response(serializer.errors, status = status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@RoleBasedAuthorizationMiddleware.require_authentication
def get_all_users(request):
    """
    API to get all users based on role permissions:
    - Admin: Can see all users
    - Agent: Can see only users and owners
    - Others: Access denied
    """
    user = getattr(request, 'user', None)

    # Extra defensive checks (decorator should have enforced auth already)
    if not user or not getattr(user, 'is_authenticated', False):
        return Response({'error': 'Authentication required'}, status=status.HTTP_401_UNAUTHORIZED)

    role = getattr(user, 'role', None)

    if role == 'admin':
        # Admin can see all users
        users = CustomUser.objects.all()
    elif role == 'agent':
        # Agent can see only users and owners
        users = CustomUser.objects.filter(role__in=['user', 'owner'])
    else:
        return Response(
            {'error': 'You do not have permission to access this resource'}, 
            status=status.HTTP_403_FORBIDDEN
        )
    
    serializer = UserListSerializer(users, many=True)
    return Response({
        'message': 'Users retrieved successfully',
        'users': serializer.data,
        'total_count': users.count()
    }, status=status.HTTP_200_OK)


@api_view(['GET'])
@RoleBasedAuthorizationMiddleware.require_authentication
def get_current_user(request):
    """
    API to get current user's complete information from request.user
    """
    user = getattr(request, 'user', None)
    if not user or not getattr(user, 'is_authenticated', False):
        return Response({'error': 'Authentication required'}, status=status.HTTP_401_UNAUTHORIZED)
    serializer = CurrentUserSerializer(user)
    
    return Response({
        'message': 'Current user information retrieved successfully',
        'user': serializer.data
    }, status=status.HTTP_200_OK)


@api_view(['PUT'])
@RoleBasedAuthorizationMiddleware.require_authentication
def update_current_user(request):
    """
    API to update current user's information
    """
    user = getattr(request, 'user', None)
    if not user or not getattr(user, 'is_authenticated', False):
        return Response({'error': 'Authentication required'}, status=status.HTTP_401_UNAUTHORIZED)
    serializer = CurrentUserSerializer(user, data=request.data, partial=True)
    
    if serializer.is_valid():
        serializer.save()
        return Response({
            'message': 'User information updated successfully',
            'user': serializer.data
        }, status=status.HTTP_200_OK)
    
    return Response({
        'error': 'Validation failed',
        'details': serializer.errors
    }, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([AllowAny])
@csrf_exempt
def logout(request):
    """
    API to logout user by clearing cookies
    """
    response = Response({
        'message': 'Logged out successfully'
    }, status=status.HTTP_200_OK)
    
    # Clear the cookies
    response.delete_cookie('access')
    response.delete_cookie('refresh')
    
    return response