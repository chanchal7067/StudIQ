from rest_framework import serializers
from .models import CustomUser, OTPTable , Service, Feature,Hostel,HostelPhoto
import re
import random
from rest_framework_simplejwt.tokens import RefreshToken


class SignupSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=100)
    email = serializers.EmailField()
    mobile = serializers.CharField(max_length=15)
    role = serializers.ChoiceField(choices=['user', 'owner', 'admin', 'agent'])

    def validate_mobile(self, value):
        pattern = r'^[6-9]\d{9}$'
        if not re.match(pattern, value):
            raise serializers.ValidationError("Enter a valid Indian mobile number")
        return value

    def validate(self, data):
        """
        Check if username, email, or mobile already exist.
        """
        username = data.get('username')
        email = data.get('email')
        mobile = data.get('mobile')

        errors = {}
        if CustomUser.objects.filter(username=username).exists():
            errors['username'] = "This username is already taken."
        if CustomUser.objects.filter(email=email).exists():
            errors['email'] = "This email is already registered."
        if CustomUser.objects.filter(mobile=mobile).exists():
            errors['mobile'] = "This mobile number is already registered."

        if errors:
            raise serializers.ValidationError(errors)

        return data

    def create(self, validated_data):
        otp = "123456"  # You can replace with random OTP generation
        user = CustomUser.objects.create(
            username=validated_data['username'],
            email=validated_data['email'],
            mobile=validated_data['mobile'],
            role=validated_data['role'],
        )
        print("Generated OTP:", otp)
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
    profile_photo = serializers.CharField(required=False, allow_blank=True, allow_null=True)

    def validate_profile_photo(self, value):
        """
        Accepts both string URLs or image file (base64 or path).
        """
        if isinstance(value, str):
            # Accept URL or base64 string
            return value
        elif hasattr(value, 'name'):
            # If it's a file object (e.g., uploaded image)
            return value
        return None

    def update(self, instance, validated_data):
        """
        Update existing user profile.
        Handles both image file and string URLs for profile_photo.
        """
        profile_photo = validated_data.pop('profile_photo', None)

        for key, value in validated_data.items():
            setattr(instance, key, value)

        if profile_photo:
            instance.profile_photo = profile_photo  # can be URL string or image

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
    
class FeatureSerializer(serializers.Serializer):
    feature_id = serializers.IntegerField(read_only=True)
    service = serializers.PrimaryKeyRelatedField(queryset=Service.objects.all())
    feature_name = serializers.CharField(max_length=255)
    created_at = serializers.DateTimeField(read_only=True)
    updated_at = serializers.DateTimeField(read_only=True)

    def create(self, validated_data):
        return Feature.objects.create(**validated_data)

    def update(self, instance, validated_data):
        instance.service = validated_data.get("service", instance.service)
        instance.feature_name = validated_data.get("feature_name", instance.feature_name)
        instance.save()
        return instance

class ServiceSerializer(serializers.Serializer):
    service_id = serializers.IntegerField(read_only=True)
    service_name = serializers.CharField(max_length=100)
    title = serializers.CharField(max_length=255)
    created_at = serializers.DateTimeField(read_only=True)
    updated_at = serializers.DateTimeField(read_only=True)

    features = FeatureSerializer(many=True, read_only=True)

    def create(self, validated_data):
        return Service.objects.create(**validated_data)

    def update(self, instance, validated_data):
        instance.service_name = validated_data.get("service_name", instance.service_name)
        instance.title = validated_data.get("title", instance.title)
        instance.save()
        return instance

class HostelSerializer(serializers.ModelSerializer):
    user = serializers.SerializerMethodField()

    class Meta:
        model = Hostel
        fields = "__all__"

    def get_user(self, obj):
        """Return username + id together as 'username (id)'."""
        if obj.user:
            return f"{obj.user.username} (ID: {obj.user.id})"
        return None    

    def validate_contact_no(self, value):
        value = value.strip().replace(" ", "")
        if not value.isdigit() or len(value) < 10:
            raise serializers.ValidationError("Contact number must be at least 10 digits.")
        return value

    def validate_pincode(self, value):
        value = value.strip().replace(" ", "")
        if not value.isdigit() or len(value) != 6:
            raise serializers.ValidationError("Pincode must be exactly 6 digits.")
        return value

class HostelPhotoSerializer(serializers.ModelSerializer): 
    class Meta:
        model = HostelPhoto 
        fields = ['id', 'hostel', 'file', 'is_banner', 'created_at', 'updated_at'] 
    
    def validate(self, data): 
        file = data.get('file')
        if not file: 
            raise serializers.ValidationError("File is required for upload.") 
        return data
