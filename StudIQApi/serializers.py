from rest_framework import serializers
from .models import CustomUser
import re
import random
from rest_framework_simplejwt.tokens import RefreshToken


class SignupSerializer(serializers.Serializer):
    username = serializers.CharField(max_length = 100)
    email = serializers.EmailField()
    mobile = serializers.CharField(max_length = 15)
    role = serializers.ChoiceField(choices = ['user','owner','admin', 'agent'])

    def validate_mobile(self,value):
        pattern = r'^[6-9]\d{9}$'

        if not re.match(pattern,value):
            raise serializers.ValidationError("Enter a valid Indian Mobile number")
        return value
    
    def create(self,validated_data):
        otp = str(random.randint(100000,999999))
        user = CustomUser.objects.create(
            username = validated_data['username'],
            email = validated_data['email'],
            mobile = validated_data['mobile'],
            role = validated_data['role'],
            otp = otp
        )
        print("generated otp", otp)
        return user
    

class VerifyOtpSerializer(serializers.Serializer):
    mobile = serializers.CharField()
    otp = serializers.CharField()

    def validate(self, data):
        mobile = data.get('mobile')
        otp = data.get('otp')

        try:
            user = CustomUser.objects.get(mobile = mobile, otp = otp)
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError("Invalid mobile or otp")
        
        user.is_verified = True
        user.otp = None
        user.save()
        
        return data
    
class LoginSerializer(serializers.Serializer):
    mobile = serializers.CharField(max_length = 15)

    def validate(self, data):
        mobile = data.get("mobile")

        try:
            user = CustomUser.objects.get(mobile = mobile)
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError("User with this mobile does not exist")
        
        if not user.is_verified:
            raise serializers.ValidationError("User not verified please verify otp first")
        
        data["user"] = user
        return data
    
class VerifyLoginOtpSerializer(serializers.Serializer):
    mobile = serializers.CharField()
    otp = serializers.CharField()

    def validate(self, data):
        mobile = data.get("mobile")
        otp = data.get("otp")

        try:
            user = CustomUser.objects.get(mobile = mobile, otp = otp)
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError("Invalid Mobile or Otp")
        
        if not user.is_verified:
            raise serializers.ValidationError("User not verified yet")
        
        user.otp = None
        user.save()

        data["user"] = user
        return data
    
class CompleteProfileSerializer(serializers.Serializer):
    id = serializers.IntegerField(read_only = True)
    username = serializers.CharField(max_length = 100, required = False)
    email = serializers.EmailField(required = False)
    role = serializers.CharField(max_length = 10, required = False)

    age = serializers.IntegerField(required = False, allow_null = True)
    dob = serializers.DateField(required = False, allow_null = True)
    father_name = serializers.CharField(max_length = 100, required = False, allow_blank = True)
    from_state = serializers.CharField(max_length = 100, required = False, allow_blank = True)
    from_city = serializers.CharField(max_length = 100, required = False, allow_blank = True)
    to_state = serializers.CharField(max_length = 100, required = False, allow_blank = True)
    to_city = serializers.CharField(max_length = 100, required = False, allow_blank = True)
    permanent_address = serializers.CharField(required = False, allow_blank = True)
    pincode = serializers.CharField(max_length = 10, required = False, allow_blank = True)
    current_address = serializers.CharField(required = False, allow_blank = True)
    hobbies = serializers.CharField(required = False, allow_blank = True)
    bio = serializers.CharField(required = False, allow_blank = True)
    interests = serializers.CharField(required = False, allow_blank = True)
    skills = serializers.CharField(required = False, allow_blank = True)
    profile_photo = serializers.ImageField(required = False, allow_null = True)

    def update(self, instance, validated_data):
        for key, value in validated_data.items():
            setattr(instance, key, value)
        instance.save()
        return instance
    
    def create(self, validated_data):
        return CustomUser.objects.create(**validated_data)
    