from django.db import models
from django.utils import timezone
from datetime import timedelta
from cloudinary.models import CloudinaryField

class CustomUser(models.Model):

    ROLE_CHOICES = (
        ('user' , 'User'),
        ('owner' , 'Owner'),
        ('admin', 'Admin'),
        ('agent', 'Agent'),
    )

    username = models.CharField(max_length = 100, unique = True)
    email = models.EmailField(unique = True)
    mobile = models.CharField(max_length = 15, unique = True)
    role = models.CharField(max_length = 10, choices = ROLE_CHOICES, default = 'user')
    is_verified = models.BooleanField(default = False)

    age = models.IntegerField(blank = True, null = True)
    dob = models.DateField(blank = True, null = True)
    father_name = models.CharField(max_length = 100,blank = True, null = True)
    adhaar_no = models.CharField(max_length = 12, blank = True, null = True)
    state = models.CharField(max_length = 100,blank = True, null = True)
    city = models.CharField(max_length = 100, blank = True, null = True)
    permanent_address = models.TextField(blank = True, null = True)
    pincode = models.CharField(max_length = 10, blank = True, null = True)
    current_address = models.TextField(blank = True, null = True)
    hobbies = models.TextField(blank = True, null = True)
    bio = models.TextField(blank = True, null = True)
    interests = models.TextField(blank = True, null = True)
    skills = models.TextField(blank = True, null = True)
    profile_photo = CloudinaryField('image', folder='profile_photo', blank=True, null=True)

    def __str__(self):
        return f"{self.username}-----------{self.role}"
    
class OTPTable(models.Model):
    user_id = models.IntegerField()
    mobile = models.CharField(max_length = 15)
    otp = models.CharField(max_length = 6)
    created_at = models.DateTimeField(auto_now_add = True)
    expired_at = models.DateTimeField(default = timezone.now() + timedelta(minutes = 5))

    def __str__(self):
        return f"{self.user_id}---------{self.otp}"    
    
class Service(models.Model):
    service_id = models.AutoField(primary_key=True)
    service_name = models.CharField(max_length=100, unique=True)
    title = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)   # auto set on insert
    updated_at = models.DateTimeField(auto_now=True)       # auto set on update

    def __str__(self):
        return self.service_name

class Feature(models.Model):
    feature_id = models.AutoField(primary_key=True)
    service = models.ForeignKey(Service, related_name="features", on_delete=models.CASCADE)
    feature_name = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.service.service_name} → {self.feature_name}"      
    
class Hostel(models.Model):
    HOSTEL_TYPE_CHOICES = [
        ("Boys", "Boys"),
        ("Girls", "Girls"),
    ]

    TAGS_CHOICES = [
        ("Luxury", "Luxury"),
        ("Standard", "Standard"),
    ]

    user = models.ForeignKey(CustomUser, on_delete = models.CASCADE, related_name = 'hostels')

    id = models.AutoField(primary_key = True)
    name = models.CharField(max_length = 255)
    tagline = models.CharField(max_length = 255, blank = True, null = True)
    city = models.CharField(max_length = 100)
    state = models.CharField(max_length = 100)
    pincode = models.CharField(max_length = 6)
    contact_no = models.CharField(max_length = 15)
    email = models.EmailField()
    starting_price = models.DecimalField(max_digits = 10, decimal_places = 2)
    total_rooms = models.IntegerField(default = 0)
    available_rooms = models.IntegerField(default = 0)
    hostel_type = models.CharField(max_length = 10, choices = HOSTEL_TYPE_CHOICES)
    meal_include = models.BooleanField(default = False)
    curfew_time = models.TimeField(null = True, blank = True)
    warden_name = models.CharField(max_length = 100, blank = True, null = True)
    average_rating = models.DecimalField(max_digits = 3, decimal_places = 1, default = 0.0)
    nearby = models.TextField(blank = True, null = True)
    common_offer = models.TextField(blank = True, null = True)
    tags = models.CharField(max_length = 20, choices = TAGS_CHOICES, default = 'Standard')
    events = models.TextField(blank = True, null = True)
    is_approved = models.BooleanField(default = False)
    approved_by = models.CharField(max_length = 100, blank = True, null = True)
    is_rejected = models.BooleanField(default = False)
    rejected_reason = models.TextField(blank = True, null = True)
    is_active = models.BooleanField(default = True)
    created_at = models.DateTimeField(auto_now_add = True)
    updated_at = models.DateTimeField(auto_now = True)
    total_views = models.IntegerField(default = 0)

    def __str__(self):
        return self.name
    
class HostelRoom(models.Model):
    ROOM_TYPE_CHOICES = [
        ('Single', 'Single'),
        ('Double', 'Double'),
        ('Triple', 'Triple'),

    ]

    AC_TYPE_CHOICES = [
        ('AC', 'AC'),
        ('Non-AC', 'Non-AC'),
    ]

    FURNISHED_CHOICES = [
        ('Furnished', 'Furnished'),
        ('Semi-Furnished', 'Semi-Furnished'),
        ('Unfurnished', 'Unfurnished'),
    ]

    BED_TYPE_CHOICES = [
        ('Single Bed','Single Bed'),
        ('Bunk Bed', 'Bunk Bed'),
        ('Double Bed', 'Double Bed'),
    ]

    id = models.AutoField(primary_key = True)
    hostel = models.ForeignKey(Hostel, on_delete = models.CASCADE, related_name = 'rooms')
    room_no = models.CharField(max_length = 20)
    room_type = models.CharField(max_length = 20, choices = ROOM_TYPE_CHOICES)
    floor_no = models.IntegerField()
    ac_type = models.CharField(max_length = 10, choices = AC_TYPE_CHOICES)
    furnished_status = models.CharField(max_length = 20, choices = FURNISHED_CHOICES)
    bed_type = models.CharField(max_length = 20, choices = BED_TYPE_CHOICES)
    price_per_month = models.DecimalField(max_digits = 10, decimal_places = 2)
    availability = models.BooleanField(default = True)
    capacity = models.IntegerField(default = 1)
    old_user_counts = models.IntegerField(default = 0)
    created_at = models.DateTimeField(auto_now_add = True)
    updated_at = models.DateTimeField(auto_now = True)

    def __str__(self):
        return f"{self.hostel.name} - Room {self.room_no}"

class HostelFacility(models.Model):
    id = models.AutoField(primary_key = True)
    hostel = models.OneToOneField(Hostel, on_delete = models.CASCADE, related_name = 'facility')
    power_backup = models.BooleanField(default = False)
    cctv = models.BooleanField(default = False)
    warden = models.BooleanField(default = False)
    visitors = models.BooleanField(default = False)
    tv_lounge = models.BooleanField(default = False)
    gym_access = models.BooleanField(default = False)
    ro_water = models.BooleanField(default = False)
    fire_safety = models.BooleanField(default = False)
    washing_machine = models.BooleanField(default = False)
    wifi = models.BooleanField(default = False)
    geyser = models.BooleanField(default = False)
    parking = models.BooleanField(default = False)
    open_terrace = models.BooleanField(default = False)
    created_at = models.DateTimeField(auto_now_add = True)
    updated_at = models.DateTimeField(auto_now = True)

    def __str__(self):
        return f"{self.hostel.name} Facilities"
    
class HostelPhoto(models.Model):
    id = models.AutoField(primary_key = True)
    hostel = models.ForeignKey(Hostel, on_delete = models.CASCADE, related_name = 'photos')
    file = CloudinaryField(resource_type = 'auto')
    is_banner = models.BooleanField(default = False)
    created_at = models.DateTimeField(auto_now_add = True)
    updated_at = models.DateTimeField(auto_now = True)

    def __str__(self):
        return f"{self.hostel.name} Photo"
    