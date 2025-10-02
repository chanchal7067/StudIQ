from django.urls import path
from .views import (
    signup, verify_otp, login, verify_login_otp, 
    complete_profile, get_all_users, 
    get_current_user, update_current_user, logout,
    service_list,create_service,service_detail,update_service,delete_service,
    feature_list,add_feature,feature_detail,update_feature,delete_feature,get_all_services_with_features
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

    # Service APIs
    path('services/', service_list, name='service-list'),  # GET all services
    path('services/create/', create_service, name='create-service'),  # POST (admin)
    path('services/<int:service_id>/', service_detail, name='service-detail'),  # GET single
    path('services/<int:service_id>/update/', update_service, name='update-service'),  # PUT (admin)
    path('services/<int:service_id>/delete/', delete_service, name='delete-service'),  # DELETE (admin)
    
    path('features/', feature_list, name='feature-list'),  # GET all
    path('features/add/', add_feature, name='add-feature'),  # POST (admin)
    path('features/<int:feature_id>/', feature_detail, name='feature-detail'),  # GET single
    path('features/<int:feature_id>/update/', update_feature, name='update-feature'),  # PUT (admin)
    path('features/<int:feature_id>/delete/', delete_feature, name='delete-feature'),  # DELETE (admin)

    # Services with features
    path('services-features/', get_all_services_with_features, name='services-features'),
]