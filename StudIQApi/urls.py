from django.urls import path
from .views import (
    signup, verify_otp, login, verify_login_otp, 
    get_complete_profile_view_byid, get_all_users, 
    get_current_user, update_current_user, logout
)

urlpatterns = [
    path("signup/", signup, name = "signup"),
    path("verify_otp/",verify_otp, name = "verify_otp" ),
    path("login/", login, name = "login"),
    path("verify_login_otp/", verify_login_otp, name = "verify_login_otp"),
    path("get_complete_profile_view_byid/<int:user_id>/", get_complete_profile_view_byid, name = "get_complete_profile_view_byid"),
    
    # New endpoints for user management
    path("users/", get_all_users, name = "get_all_users"),
    path("me/", get_current_user, name = "get_current_user"),
    path("me/update/", update_current_user, name = "update_current_user"),
    path("logout/", logout, name = "logout"),
]