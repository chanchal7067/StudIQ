from django.urls import path
from .views import signup
from .views import verify_otp,login, verify_login_otp , get_complete_profile_view_byid

urlpatterns = [
    path("signup/", signup, name = "signup"),
    path("verify_otp/",verify_otp, name = "verify_otp" ),
    path("login/", login, name = "login"),
    path("verify_login_otp/", verify_login_otp, name = "verify_login_otp"),
    path("get_complete_profile_view_byid/<int:user_id>/", get_complete_profile_view_byid, name = "get_complete_profile_view_byid")
    
]