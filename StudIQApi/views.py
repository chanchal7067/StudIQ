from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from .serializers import SignupSerializer,VerifyOtpSerializer,LoginSerializer,VerifyLoginOtpSerializer, CompleteProfileSerializer
from rest_framework_simplejwt.tokens import RefreshToken
import random
from .models import CustomUser

@api_view(['POST'])
def signup(request):
    serializer = SignupSerializer(data = request.data)
    if serializer.is_valid():
        serializer.save()
        return Response({"message" : "Signup Successfull Otp sent to your mobile"}, status = status.HTTP_201_CREATED)
    return Response(serializer.error, status = status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
def verify_otp(request):
    serializer = VerifyOtpSerializer(data = request.data)
    if serializer.is_valid():
        return Response({"Message" :"otp verified successfully, you can now log in"}, status = status.HTTP_200_OK)
    return Response(serializer.errors, status = status.HTTP_400_BAD_REQUEST)

def set_tokens_as_cookies(response, user):
    refresh = RefreshToken.for_user(user)
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
def login(request):
    serializer = LoginSerializer(data = request.data)
    if serializer.is_valid():
        user = serializer.validated_data["user"]
        otp = str(random.randint(100000,999999))
        user.otp = otp
        user.save()

        print("Login OTP:", otp)

        return Response({"Message" : "Otp sent to your mobile"}, status = status.HTTP_200_OK)
    
    return Response(serializer.errors, status = status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
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
        