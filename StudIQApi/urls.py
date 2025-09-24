from django.urls import path
from .views import (
    signup, verify_otp, login, verify_login_otp, 
    complete_profile, get_all_users, 
    get_current_user, update_current_user, logout,
    service_list_create, service_detail,
    feature_list_create, feature_detail,

)

urlpatterns = [
    path("signup/", signup, name = "signup"),
    path("verify_otp/",verify_otp, name = "verify_otp" ),
    path("login/", login, name = "login"),
    path("verify_login_otp/", verify_login_otp, name = "verify_login_otp"),
    path("complete-profile/", complete_profile, name = "complete_profile"),
    
    # New endpoints for user management
    path("users/", get_all_users, name = "get_all_users"),
    path("me/", get_current_user, name = "get_current_user"),
    path("me/update/", update_current_user, name = "update_current_user"),
    path("logout/", logout, name = "logout"),

    path("service_list_create/", service_list_create, name = "service_list_create"),
    path("service_detail/<int:pk>/", service_detail, name = "service_detail"),
    path("feature_list_create/", feature_list_create, name = "feature_list_create"),
    path("feature_detail/<int:pk>/", feature_detail, name = "feature_detail")

    
]