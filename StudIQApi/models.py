from django.db import models

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
    otp = models.CharField(max_length = 6, blank = True, null = True)
    is_verified = models.BooleanField(default = False)

    age = models.IntegerField(blank = True, null = True)
    dob = models.DateField(blank = True, null = True)
    father_name = models.CharField(max_length = 100,blank = True, null = True)
    from_state = models.CharField(max_length = 100,blank = True, null = True)
    from_city = models.CharField(max_length = 100, blank = True, null = True)
    to_state = models.CharField(max_length = 100, blank = True, null = True)
    to_city = models.CharField(max_length = 100, blank = True, null = True)
    permanent_address = models.TextField(blank = True, null = True)
    pincode = models.CharField(max_length = 10, blank = True, null = True)
    current_address = models.TextField(blank = True, null = True)
    hobbies = models.TextField(blank = True, null = True)
    bio = models.TextField(blank = True, null = True)
    interests = models.TextField(blank = True, null = True)
    skills = models.TextField(blank = True, null = True)
    profile_photo = models.ImageField(upload_to = "profile_photo/", blank = True, null = True)

    def __str__(self):
        return f"{self.username}-----------{self.role}"
    
class OTPTable(models.Model):
    user_id = models.IntegerField()
    mobile = models.CharField(max_length = 15)
    otp = models.CharField(max_length = 6)
    created_at = models.DateTimeField(auto_now_add = True)

    def __str__(self):
        return f"{self.user_id}---------{self.otp}"    