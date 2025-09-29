from django.urls import path
from .views import (
    signup, verify_otp, login, verify_login_otp, 
    complete_profile, get_all_users, 
    get_current_user, update_current_user, logout,
    add_feature,create_service,delete_feature,delete_service,
    update_feature,get_all_services_with_features

)

urlpatterns = [
    path("signup/", signup, name = "signup"),
    path("verify_otp/",verify_otp, name = "verify_otp" ),
    path("login/", login, name = "login"),
    path("verify_login_otp/", verify_login_otp, name = "verify_login_otp"),
    path("complete-profile/", complete_profile, name = "complete_profile"),
    
    # New endpoints for user management
    path("users/", get_all_users, name = "get_all_users"),
    path("get-current-user/", get_current_user, name = "get_current_user"),
    path("update-current-user/", update_current_user, name = "update_current_user"),
    path("logout/", logout, name = "logout"),

    path("create_service/", create_service, name = "create_service"),
    path("delete_service/<int:service_id>/", delete_service, name = "delete_service"),
    path("add_feature/", add_feature, name = "add_feature"),
    path("delete_feature/<int:feature_id>/", delete_feature, name = "delete_feature"),
    path("update_feature/<int:feature_id>/", update_feature, name = "update_feature"),
    path("get_all_services_with_features/", get_all_services_with_features, name = "get_all_services_with_features"),
    

    
]