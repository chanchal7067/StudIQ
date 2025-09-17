from django.urls import path
from .views import signup
from .views import verify_otp
# from .views import login

urlpatterns = [
    path("signup/", signup, name = "signup"),
    path("verify_otp/",verify_otp, name = "verify_otp" )
    # path("login/", login, name = "login"),
]