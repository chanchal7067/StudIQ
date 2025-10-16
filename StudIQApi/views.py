from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from .serializers import SignupSerializer,VerifyOtpSerializer,LoginSerializer,VerifyLoginOtpSerializer, CompleteProfileSerializer, UserListSerializer, CurrentUserSerializer, ServiceSerializer, FeatureSerializer, HostelSerializer, HostelPhotoSerializer
from .middleware import RoleBasedAuthorizationMiddleware
from django.http import JsonResponse
from rest_framework_simplejwt.tokens import RefreshToken
import random
from .models import CustomUser, OTPTable , Service, Feature,Hostel

from django.views.decorators.csrf import csrf_exempt
from functools import wraps

# -------------------- Decorators --------------------

def admin_required(view_func):
    """
    Decorator to allow only users with role 'admin' to access the view.
    """
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        user = getattr(request, 'user', None)
        if not user or not getattr(user, 'is_authenticated', False):
            return Response({"error": "Authentication required"}, status=status.HTTP_401_UNAUTHORIZED)
        if getattr(user, 'role', None) != 'admin':
            return Response({"error": "Admin access required"}, status=status.HTTP_403_FORBIDDEN)
        return view_func(request, *args, **kwargs)
    return _wrapped_view


@api_view(['POST'])
@permission_classes([AllowAny])
@csrf_exempt
def signup(request):
    serializer = SignupSerializer(data=request.data)
    if serializer.is_valid():
        user, otp = serializer.save()
        OTPTable.objects.create(
            user_id=user.id,
            mobile=user.mobile,
            otp=otp
        )
        return Response({
            "status": "success",
            "message": "Signup successful! OTP sent to your mobile.",
            "user_id": user.id,
            "mobile": user.mobile
        }, status=status.HTTP_201_CREATED)

    # Return validation errors
    return Response({
        "status": "error",
        "errors": serializer.errors
    }, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny])
@csrf_exempt
def verify_otp(request):
    serializer = VerifyOtpSerializer(data = request.data)
    if serializer.is_valid():
        return Response({"status": "success","Message" :"otp verified successfully, you can now log in"}, status = status.HTTP_200_OK)
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

        return Response({"status": "success","Message" : "Otp sent to your mobile"}, status = status.HTTP_200_OK)
    
    return Response(serializer.errors, status = status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny])
@csrf_exempt
def verify_login_otp(request):
    serializer = VerifyLoginOtpSerializer(data = request.data)
    if serializer.is_valid():
        user = serializer.validated_data["user"]
        response = Response({"status": "success","Message" : "Login Successful"}, status = status.HTTP_200_OK)
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
        return Response({
            "status": "success",
            "message": "Profile details fetched successfully",
            "data": serializer.data
        }, status=status.HTTP_200_OK)

   # -------------------- UPDATE PROFILE --------------------
    elif request.method == "PUT":
        data = request.data.copy()

        # ✅ Allow string URL for profile_photo
        profile_photo = data.get('profile_photo')
        if profile_photo and isinstance(profile_photo, str):
            user.profile_photo = profile_photo  # Directly assign string (URL/Base64)

        serializer = CompleteProfileSerializer(user, data=data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({
                "status": "success",
                "message": "Profile updated successfully",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        return Response({
            "status": "error",
            "errors": serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

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
        "status": "success",
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
        "status": "success",
        'message': 'Current user information retrieved successfully',
        'user': serializer.data
    }, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([AllowAny])
@csrf_exempt
def logout(request):
    """
    API to logout user by clearing cookies
    """
    response = Response({
        "status": "success",
        'message': 'Logged out successfully'
    }, status=status.HTTP_200_OK)
    
    # Clear the cookies
    response.delete_cookie('access')
    response.delete_cookie('refresh')
    
    return response

# -------------------- Service APIs --------------------

@api_view(['GET'])
def service_list(request):
    services = Service.objects.all()
    serializer = ServiceSerializer(services, many=True)
    return Response({
        "status": "success",
        "message": "Services fetched successfully",
        "total": services.count(),
        "data": serializer.data
    }, status=status.HTTP_200_OK)


@api_view(['POST'])
@admin_required
def create_service(request):
    serializer = ServiceSerializer(data=request.data)
    if serializer.is_valid():
        service = serializer.create(serializer.validated_data)
        return Response({"status": "success","message": "Service Created Successfully", "data": ServiceSerializer(service).data}, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['PUT'])
@admin_required
def update_service(request, service_id):
    try:
        service = Service.objects.get(pk=service_id)
    except Service.DoesNotExist:
        return Response({"status": "error", "message": "Service not found"}, status=status.HTTP_404_NOT_FOUND)
    serializer = ServiceSerializer(service, data=request.data, partial=True)
    if serializer.is_valid():
        service = serializer.update(service, serializer.validated_data)
        return Response({"status": "success","message": "Service Updated Successfully", "data": ServiceSerializer(service).data}, status=status.HTTP_200_OK)
    return Response({"status": "error", "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['DELETE'])
@admin_required
def delete_service(request, service_id):
    try:
        service = Service.objects.get(pk=service_id)
        service.delete()
        return Response({"status": "success","message": "Service deleted successfully"}, status=status.HTTP_200_OK)
    except Service.DoesNotExist:
        return Response({"status": "error", "message": "Service not found"}, status=status.HTTP_404_NOT_FOUND)


@api_view(['GET'])
def service_detail(request, service_id):
    try:
        service = Service.objects.get(pk=service_id)
    except Service.DoesNotExist:
        return Response({"status": "error","error": "Service not found"}, status=status.HTTP_404_NOT_FOUND)
    serializer = ServiceSerializer(service)
    return Response({
        "status": "success",
        "message": "Service details fetched successfully",
        "data": serializer.data
    }, status=status.HTTP_200_OK)


# -------------------- Feature APIs --------------------

@api_view(['GET'])
def feature_list(request):
    features = Feature.objects.all()
    serializer = FeatureSerializer(features, many=True)
    return Response({
        "status": "success",
        "message": "Features fetched successfully",
        "total": features.count(),
        "data": serializer.data
    }, status=status.HTTP_200_OK)


@api_view(['POST'])
@admin_required
def add_feature(request):
    serializer = FeatureSerializer(data=request.data)
    if serializer.is_valid():
        feature = serializer.create(serializer.validated_data)
        return Response({"status": "success","message": "Feature added Successfully", "data": FeatureSerializer(feature).data}, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['PUT'])
@admin_required
def update_feature(request, feature_id):
    try:
        feature = Feature.objects.get(pk=feature_id)
    except Feature.DoesNotExist:
        return Response({"status": "error", "message": "Feature not found"}, status=status.HTTP_404_NOT_FOUND)
    serializer = FeatureSerializer(feature, data=request.data, partial=True)
    if serializer.is_valid():
        feature = serializer.update(feature, serializer.validated_data)
        return Response({"status": "success","message": "Feature Updated Successfully", "data": FeatureSerializer(feature).data}, status=status.HTTP_200_OK)
    return Response({"status": "error", "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['DELETE'])
@admin_required
def delete_feature(request, feature_id):
    try:
        feature = Feature.objects.get(pk=feature_id)
        feature.delete()
        return Response({"status": "success","message": "Feature deleted Successfully"}, status=status.HTTP_200_OK)
    except Feature.DoesNotExist:
        return Response({"status": "error", "message": "Feature not found"}, status=status.HTTP_404_NOT_FOUND)


@api_view(['GET'])
def feature_detail(request, feature_id):
    try:
        feature = Feature.objects.get(pk=feature_id)
    except Feature.DoesNotExist:
        return Response({"status": "error","error": "Feature not found"}, status=status.HTTP_404_NOT_FOUND)
    serializer = FeatureSerializer(feature)
    return Response({
        "status": "success",
        "message": "Feature details fetched successfully",
        "data": serializer.data
    }, status=status.HTTP_200_OK)


@api_view(['GET'])
def get_all_services_with_features(request):
    services = Service.objects.all()
    serializer = ServiceSerializer(services, many=True)
    return Response({"status": "success","services": serializer.data}, status=status.HTTP_200_OK)


# Hostel Services api
@api_view(['POST'])
@RoleBasedAuthorizationMiddleware.require_roles(['owner'])
def create_hostel(request):
    """
    API for owner to create a new hostel.
    The logged-in owner (from access token) is automatically assigned to the hostel.
    """

    user = getattr(request, 'user', None)

    if not user or not getattr(user, 'is_authenticated', False):
        return Response(
            {"error": "Authentication required"},
            status=status.HTTP_401_UNAUTHORIZED
        )

    serializer = HostelSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save(user=user)
        return Response({
            "status": "success",
            "message": "Hostel created successfully",
            "data": serializer.data
        }, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['PUT'])
@RoleBasedAuthorizationMiddleware.require_roles(['owner'])
def update_hostel_by_id(request, hostel_id):
    """
    API for owner to update a hostel by its ID.
    """
    try:
        hostel = Hostel.objects.get(id=hostel_id)
    except Hostel.DoesNotExist:
        return Response({"status":"error","error": "Hostel not found"}, status=status.HTTP_404_NOT_FOUND)

    serializer = HostelSerializer(hostel, data=request.data, partial=True)
    if serializer.is_valid():
        serializer.save()
        return Response({
            "status": "success",
            "message": "Hostel updated successfully",
            "data": serializer.data
        }, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@RoleBasedAuthorizationMiddleware.require_roles(['admin'])
def get_all_hostels(request):
    """
    API for admin to view all hostels.
    """
    hostels = Hostel.objects.all().order_by('-created_at')
    serializer = HostelSerializer(hostels, many=True)
    return Response({
        "status": "success",
        "message": "All hostels retrieved successfully",
        "total": hostels.count(),
        "data": serializer.data
    }, status=status.HTTP_200_OK)

@api_view(['DELETE'])
@RoleBasedAuthorizationMiddleware.require_roles(['admin'])
def delete_hostel_by_id(request, hostel_id):
    """
    API for admin to delete a hostel by ID.
    """
    try:
        hostel = Hostel.objects.get(id=hostel_id)
        hostel.delete()
        return Response({"status": "success", "message": "Hostel deleted successfully"}, status=status.HTTP_200_OK)
    except Hostel.DoesNotExist:
        return Response({"status": "error", "message": "Hostel not found"}, status=status.HTTP_404_NOT_FOUND)

@api_view(['PUT'])
@RoleBasedAuthorizationMiddleware.require_roles(['admin'])
def approve_or_reject_hostel(request, hostel_id):
    """
    API for admin to approve or reject a hostel.
    Expected body: { "action": "approve" } or { "action": "reject", "reason": "..." }
    """
    try:
        hostel = Hostel.objects.get(id=hostel_id)
    except Hostel.DoesNotExist:
        return Response({"status": "error", "message": "Hostel not found"}, status=status.HTTP_404_NOT_FOUND)

    action = request.data.get('action')

    if action == 'approve':
        hostel.is_approved = True
        hostel.is_rejected = False
        hostel.rejected_reason = None
        hostel.approved_by = request.user.username
        hostel.save()
        return Response({"status": "success","message": "Hostel approved successfully"}, status=status.HTTP_200_OK)

    elif action == 'reject':
        reason = request.data.get('reason', 'No reason provided')
        hostel.is_rejected = True
        hostel.is_approved = False
        hostel.rejected_reason = reason
        hostel.approved_by = None
        hostel.save()
        return Response({
            "status": "success",
            "message": "Hostel rejected successfully",
            "reason": reason
        }, status=status.HTTP_200_OK)

    else:
        return Response(
            {"status": "error", "message": "Invalid action. Use 'approve' or 'reject'."},
            status=status.HTTP_400_BAD_REQUEST
        )
    
@api_view(['PUT'])
@RoleBasedAuthorizationMiddleware.require_roles(['admin', 'owner'])
def change_status_by_id(request, hostel_id):
    """
    API to activate or deactivate a hostel (admin and owner allowed).
    Expected body: { "status": true } or { "status": false }
    """
    try:
        hostel = Hostel.objects.get(id=hostel_id)
    except Hostel.DoesNotExist:
        return Response({"status": "error", "message": "Hostel not found"}, status=status.HTTP_404_NOT_FOUND)

    status_value = request.data.get('status')
    if status_value is None:
        return Response({"status": "error", "message": "Status field (true/false) is required"}, status=status.HTTP_400_BAD_REQUEST)

    hostel.is_active = bool(status_value)
    hostel.save()
    return Response({
        "status": "success",
        "message": f"Hostel {'activated' if hostel.is_active else 'deactivated'} successfully",
        "id": hostel.id,
        "is_active": hostel.is_active
    }, status=status.HTTP_200_OK)    

@api_view(['GET'])
def get_hostel_by_id(request, hostel_id):
    """
    Public API to view a single hostel's details by ID.
    Accessible by anyone (no authentication required).
    """
    try:
        hostel = Hostel.objects.get(id=hostel_id)
    except Hostel.DoesNotExist:
        return Response(
            {"status": "error", "error": "Hostel not found"},
            status=status.HTTP_404_NOT_FOUND
        )

    serializer = HostelSerializer(hostel)
    return Response({
        "status": "success",
        "message": "Hostel details fetched successfully",
        "data": serializer.data
    }, status=status.HTTP_200_OK)


@api_view(['GET'])
def get_all_approved_hostels(request):
    """
    Public API to get a list of all approved and active hostels.
    Accessible by anyone (no authentication required).
    """
    hostels = Hostel.objects.filter(is_approved=True, is_active=True).order_by('-created_at')
    serializer = HostelSerializer(hostels, many=True)
    return Response({
        "status": "success",
        "message": "Approved hostels fetched successfully",
        "total": hostels.count(),
        "data": serializer.data
    }, status=status.HTTP_200_OK)

@api_view(['POST'])
@RoleBasedAuthorizationMiddleware.require_roles(['owner'])
def upload_hostel_image(request, hostel_id):
    """
    API for owner to upload an image to a hostel (Cloudinary auto handles storage).
    """
    try:
        hostel = Hostel.objects.get(id=hostel_id)
    except Hostel.DoesNotExist:
        return Response({"status": "error", "message": "Hostel not found"}, status=status.HTTP_404_NOT_FOUND)

    serializer = HostelPhotoSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save(hostel=hostel)
        return Response({
            "status": "success",
            "message": "Image uploaded successfully",
            "data": serializer.data
        }, status=status.HTTP_201_CREATED)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@RoleBasedAuthorizationMiddleware.require_roles(['owner'])
def upload_hostel_video(request, hostel_id):
    """
    API for owner to upload a video to a hostel (Cloudinary auto detects type).
    """
    try:
        hostel = Hostel.objects.get(id=hostel_id)
    except Hostel.DoesNotExist:
        return Response({"status": "error", "message": "Hostel not found"}, status=status.HTTP_404_NOT_FOUND)

    serializer = HostelPhotoSerializer(data=request.data)
    if serializer.is_valid():
        serializer.save(hostel=hostel)
        return Response({
            "status": "success",
            "message": "Video uploaded successfully",
            "data": serializer.data
        }, status=status.HTTP_201_CREATED)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@RoleBasedAuthorizationMiddleware.require_roles(['owner'])
def get_owner_hostels(request):
    """
    API for owners to get all hostels they have created.
    Each owner will only see their own hostels.
    """
    user = getattr(request, 'user', None)
    if not user or not getattr(user, 'is_authenticated', False):
        return Response(
            {"error" : "Authentication required"},
            status = status.HTTP_401_UNAUTHORIZED
        )
    hostels = Hostel.objects.filter(user = user).order_by('-created_at')
    if not hostels.exists():
        return Response(
            {"message" : "You have not created any hostels yet"},
            status = status.HTTP_200_OK
        )
    serializer = HostelSerializer(hostels, many = True)
    return Response({
        "status" : "Success",
        "message" : "Hostels retrieved successfully",
        "total_hostels" : hostels.count(),
        "data" : serializer.data
    }, status = status.HTTP_200_OK)

@api_view(['GET'])
@RoleBasedAuthorizationMiddleware.require_roles(['owner'])
def get_owner_hostel_byid(request, hostel_id):
    """
    API for an owner to get details of a specific hostel they own.
    Only the logged-in owner can access their own hostel details.
    Other owners or admins cannot access this.
    """
    user = getattr(request, 'user', None)
    if not user or not getattr(user, 'is_authenticated', False):
        return Response(
            {"error" : "Authentication required"},
            status = status.HTTP_401_UNAUTHORIZED
        )
    try:
        hostel = Hostel.objects.get(id = hostel_id)
    except Hostel.DoesNotExist:
        return Response(
            {"error" : "Hostel Not Found"},
            status = status.HTTP_404_NOT_FOUND
        )
    if hostel.user != user:
        return Response(
            {"error" : "You do not have permission to view this Hostel Detail"},
            status = status.HTTP_403_FORBIDDEN
        )
    serializer = HostelSerializer(hostel)
    return Response({
        "status" : "Success",
        "message" : "Hostel details retrieved successfully",
        "data" : serializer.data
    }, status = status.HTTP_200_OK)    