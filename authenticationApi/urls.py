from django.urls import path
from .views import (SignInApiView, SignUpApiView, ResetAPIView,
                    UserApiView, RefreshTokenAPIView, ResetAPIView, ForgetAPIView, 
                    SignOutApiView)

app_name = "user"

urlpatterns = [
    path('user/signup/', SignUpApiView.as_view()),
    path('user/signin/', SignInApiView.as_view()),
    path('user/user/', UserApiView.as_view()),
    path('user/refresh/', RefreshTokenAPIView.as_view()),
    path('user/reset/<str:token>/', ResetAPIView.as_view()),
    path('user/forget/', ForgetAPIView.as_view()),
    path('user/logout/', SignOutApiView.as_view()),
]
