from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from .serializers import SignupSerializer,VerifyOtpSerializer,LoginSerializer,VerifyLoginOtpSerializer, CompleteProfileSerializer, UserListSerializer, CurrentUserSerializer, ServiceSerializer, FeatureSerializer
from .middleware import RoleBasedAuthorizationMiddleware
from django.http import JsonResponse
from rest_framework_simplejwt.tokens import RefreshToken
import random
from .models import CustomUser, OTPTable , Service, Feature

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
    refresh['user_id'] = user.id
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
        otp = 123456
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
    
@api_view(['GET', 'PUT'])
@RoleBasedAuthorizationMiddleware.require_authentication
def complete_profile(request):
    """
    API for logged-in user to view or update (complete) their own profile
    - GET: Retrieve own profile
    - PUT: Update own profile (from access token)
    """
    user = getattr(request, 'user', None)

    if not user or not getattr(user, 'is_authenticated', False):
        return Response(
            {"error": "Authentication required"},
            status=status.HTTP_401_UNAUTHORIZED
        )

    if request.method == "GET":
        serializer = CompleteProfileSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)

    elif request.method == "PUT":
        serializer = CompleteProfileSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {
                    "message": "Profile updated successfully",
                    "profile": serializer.data
                },
                status=status.HTTP_200_OK
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



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

# ---------- Service APIs ----------
@api_view(['GET', 'POST'])
def service_list_create(request):
    if request.method == 'GET':
        services = Service.objects.all()
        serializer = ServiceSerializer(services, many=True)
        return Response(serializer.data)

    elif request.method == 'POST':
        serializer = ServiceSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', 'PUT', 'DELETE'])
def service_detail(request, pk):
    try:
        service = Service.objects.get(pk=pk)
    except Service.DoesNotExist:
        return Response({"error": "Service not found"}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        serializer = ServiceDetailSerializer(service)
        return Response(serializer.data)

    elif request.method == 'PUT':
        serializer = ServiceSerializer(service, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'DELETE':
        service.delete()
        return Response({"message": "Service deleted successfully"}, status=status.HTTP_204_NO_CONTENT)


# ---------- Feature APIs ----------
@api_view(['GET', 'POST'])
def feature_list_create(request):
    if request.method == 'GET':
        features = Feature.objects.all()
        serializer = FeatureSerializer(features, many=True)
        return Response(serializer.data)

    elif request.method == 'POST':
        serializer = FeatureSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', 'PUT', 'DELETE'])
def feature_detail(request, pk):
    try:
        feature = Feature.objects.get(pk=pk)
    except Feature.DoesNotExist:
        return Response({"error": "Feature not found"}, status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        serializer = FeatureSerializer(feature)
        return Response(serializer.data)

    elif request.method == 'PUT':
        serializer = FeatureSerializer(feature, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    elif request.method == 'DELETE':
        feature.delete()
        return Response({"message": "Feature deleted successfully"}, status=status.HTTP_204_NO_CONTENT)

@api_view(['POST'])
def create_service(request):
    serializer = ServiceSerializer(data = request.data)
    if serializer.is_valid():
        service = serializer.create(serializer.validated_data)
        response_serializer = ServiceSerializer(service)
        return Response({"message" : "Service Created Successfully","data" : response_serializer.data}, status = status.HTTP_201_CREATED)
    return Response(serializer.errors, status = status.HTTP_400_BAD_REQUEST)

@api_view(["DELETE"])
def delete_service(request, service_id):
    try:
        service = Service.objects.get(pk = service_id)
        service.delete()
        return Response({"message" : "service deleted successfully"}, status = status.HTTP_200_OK)
    except Service.DoesNotExist:
        return Response({"error" : "service not found"}, status = status.HTTP_404_NOT_FOUND)
    
@api_view(["POST"])
def add_feature(request):
    serializer = FeatureSerializer(data = request.data)
    if serializer.is_valid():
        feature = serializer.create(serializer.validated_data)
        response_serializer = FeatureSerializer(feature)
        return Response({"message" : "Feature added Successfully", "data" : response_serializer.data}, status = status.HTTP_201_CREATED)
    return Response(serializer.errors, status = status.HTTP_400_BAD_REQUEST)

@api_view(["DELETE"])
def delete_feature(request, feature_id):
    try:
        feature = Feature.objects.get(pk = feature_id)
        feature.delete()
        return Response({"message" : "feature deleted Successfully"}, status = status.HTTP_200_OK)
    except Feature.DoesNotExist:
        return Response({"error" : "Feature Not Found"}, status = status.HTTP_404_NOT_FOUND)
    
@api_view(["PUT"])
def update_feature(request, feature_id):
    try:
        feature = Feature.objects.get(pk = feature_id)
    except Feature.DoesNotExist:
        return Response({"error" : "feature not found"}, status = status.HTTP_404_NOT_FOUND)
    
    serializer = FeatureSerializer(feature, data = request.data, partial = True)
    if serializer.is_valid():
        updated_feature = serializer.update(feature, serializer.validated_data)
        response_serializer = FeatureSerializer(updated_feature)
        return Response({"message" : "Feature Updated Successfully", "data" : response_serializer.data}, status = status.HTTP_200_OK)
    return Response(serializer.errors, status = status.HTTP_400_BAD_REQUEST)

@api_view(["GET"])
def get_all_services_with_features(request):
    services = Service.objects.all()
    serializer = ServiceSerializer(services, many = True)
    return Response({"services" : serializer.data}, status = status.HTTP_200_OK)