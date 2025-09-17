from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from .serializers import SignupSerializer,VerifyOtpSerializer

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

