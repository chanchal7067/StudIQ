from rest_framework import serializers
from .models import CustomUser, OTPTable , Feature, Service
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
        otp = "123456"
        user = CustomUser.objects.create(
            username = validated_data['username'],
            email = validated_data['email'],
            mobile = validated_data['mobile'],
            role = validated_data['role'],
            
        )
        print("generated otp", otp)
        return user, otp
    

class VerifyOtpSerializer(serializers.Serializer):
    mobile = serializers.CharField()
    otp = serializers.CharField()

    def validate(self, data):
        mobile = data.get('mobile')
        otp = data.get('otp')

        try:
            otp_record = OTPTable.objects.filter(mobile = mobile, otp = otp).last()
            if not otp_record:
                raise serializers.ValidationError("Invalid mobile or otp")
            
            user = CustomUser.objects.get(mobile = mobile)
        
            user.is_verified = True
            user.save()
            otp_record.delete()
        
            return data
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError("User not found")
    
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
            otp_record = OTPTable.objects.filter(mobile = mobile, otp = otp).last()
            if not otp_record:
                raise serializers.ValidationError("Invalid mobile or otp")
            
            user = CustomUser.objects.get(mobile = mobile)

            if not user.is_verified:
                raise serializers.ValidationError("User not verified yet, complete signup first")
            
            otp_record.delete()
            data["user"] = user
            return data

        except CustomUser.DoesNotExist:
            raise serializers.ValidationError("User Not found")
    
class CompleteProfileSerializer(serializers.Serializer):
    id = serializers.IntegerField(read_only = True)
    username = serializers.CharField(max_length = 100, required = False)
    email = serializers.EmailField(required = False)
    role = serializers.CharField(max_length = 10, required = False)

    age = serializers.IntegerField(required = False, allow_null = True)
    dob = serializers.DateField(required = False, allow_null = True)
    father_name = serializers.CharField(max_length = 100, required = False, allow_blank = True)
    adhaar_no = serializers.CharField(max_length = 12, required = False, allow_blank = True)
    state = serializers.CharField(max_length = 100, required = False, allow_blank = True)
    city = serializers.CharField(max_length = 100, required = False, allow_blank = True)
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


class UserListSerializer(serializers.Serializer):
    id = serializers.IntegerField(read_only = True)
    username = serializers.CharField(max_length = 100)
    email = serializers.EmailField()
    mobile = serializers.CharField(max_length = 15)
    role = serializers.CharField(max_length = 20)
    is_verified = serializers.BooleanField()
    age = serializers.IntegerField(required = False, allow_null =True)
    state = serializers.CharField(max_length = 100, required = False, allow_blank = True)
    city = serializers.CharField(max_length = 100, required = False, allow_blank = True)
    
    def create(self, validated_data):
        return CustomUser.objects.create(**validated_data)
    
    def update(self, instance, validated_data):
        # updating an existing CustomUser Object

        instance.username = validated_data.get("username", instance.username)
        instance.email = validated_data.get("email", instance.email)
        instance.mobile = validated_data.get("mobile", instance.mobile)
        instance.role = validated_data.get("role", instance.role)
        instance.is_verified = validated_data.get("is_verified", instance.is_verified)
        instance.age = validated_data.get("age", instance.age)
        instance.state = validated_data.get("state", instance.state)
        instance.city = validated_data.get("city", instance.city)
        instance.save()
        return instance




class CurrentUserSerializer(serializers.Serializer):
    """
    Manual serializer for current user's complete information
    """

    id = serializers.IntegerField(read_only=True)
    username = serializers.CharField(max_length=100)
    email = serializers.EmailField()
    mobile = serializers.CharField(max_length=15)
    role = serializers.CharField(max_length=20)
    is_verified = serializers.BooleanField()

    age = serializers.IntegerField(required=False, allow_null=True)
    dob = serializers.DateField(required=False, allow_null=True)
    father_name = serializers.CharField(max_length=100, required=False, allow_blank=True)

    state = serializers.CharField(max_length=100, required=False, allow_blank=True)
    city = serializers.CharField(max_length=100, required=False, allow_blank=True)

    permanent_address = serializers.CharField(max_length=255, required=False, allow_blank=True)
    pincode = serializers.CharField(max_length=10, required=False, allow_blank=True)
    current_address = serializers.CharField(max_length=255, required=False, allow_blank=True)

    hobbies = serializers.CharField(max_length=255, required=False, allow_blank=True)
    bio = serializers.CharField(max_length=500, required=False, allow_blank=True)
    interests = serializers.CharField(max_length=255, required=False, allow_blank=True)
    skills = serializers.CharField(max_length=255, required=False, allow_blank=True)

    profile_photo = serializers.ImageField(required=False, allow_null=True)

    def create(self, validated_data):
        """
        Create a new CustomUser object from validated data
        """
        return CustomUser.objects.create(**validated_data)

    def update(self, instance, validated_data):
        """
        Update an existing CustomUser object with validated data
        """
        instance.username = validated_data.get('username', instance.username)
        instance.email = validated_data.get('email', instance.email)
        instance.mobile = validated_data.get('mobile', instance.mobile)
        instance.role = validated_data.get('role', instance.role)
        instance.is_verified = validated_data.get('is_verified', instance.is_verified)

        instance.age = validated_data.get('age', instance.age)
        instance.dob = validated_data.get('dob', instance.dob)
        instance.father_name = validated_data.get('father_name', instance.father_name)

        instance.state = validated_data.get('state', instance.state)
        instance.city = validated_data.get('city', instance.city)
        
        instance.permanent_address = validated_data.get('permanent_address', instance.permanent_address)
        instance.pincode = validated_data.get('pincode', instance.pincode)
        instance.current_address = validated_data.get('current_address', instance.current_address)

        instance.hobbies = validated_data.get('hobbies', instance.hobbies)
        instance.bio = validated_data.get('bio', instance.bio)
        instance.interests = validated_data.get('interests', instance.interests)
        instance.skills = validated_data.get('skills', instance.skills)

        instance.profile_photo = validated_data.get('profile_photo', instance.profile_photo)

        instance.save()
        return instance
    

# --------- Feature Serializer ---------
class FeatureSerializer(serializers.Serializer):
    id = serializers.IntegerField(read_only=True)
    service_id = serializers.IntegerField()   # we accept service_id manually
    feature_title = serializers.CharField(max_length=200)
    feature_icon = serializers.CharField(max_length=50, required=False, allow_blank=True)
    feature_description = serializers.CharField(required=False, allow_blank=True)

    def create(self, validated_data):
        return Feature.objects.create(
            service_id=validated_data["service_id"],
            feature_title=validated_data["feature_title"],
            feature_icon=validated_data.get("feature_icon", ""),
            feature_description=validated_data.get("feature_description", "")
        )

    def update(self, instance, validated_data):
        instance.service_id = validated_data.get("service_id", instance.service_id)
        instance.feature_title = validated_data.get("feature_title", instance.feature_title)
        instance.feature_icon = validated_data.get("feature_icon", instance.feature_icon)
        instance.feature_description = validated_data.get("feature_description", instance.feature_description)
        instance.save()
        return instance


# --------- Service Serializer ---------
class ServiceSerializer(serializers.Serializer):
    id = serializers.IntegerField(read_only=True)
    service_name = serializers.CharField(max_length=100)
    service_description = serializers.CharField(required=False, allow_blank=True)

    def create(self, validated_data):
        return Service.objects.create(**validated_data)

    def update(self, instance, validated_data):
        instance.service_name = validated_data.get("service_name", instance.service_name)
        instance.service_description = validated_data.get("service_description", instance.service_description)
        instance.save()
        return instance


# --------- Service Detail Serializer (with features) ---------
class ServiceDetailSerializer(ServiceSerializer):
    features = serializers.SerializerMethodField()

    def get_features(self, obj):
        features = Feature.objects.filter(service=obj)
        return FeatureSerializer(features, many=True).data



