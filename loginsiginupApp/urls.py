from django.urls import path
from loginsiginupApp.views import UserRegistrationView,LoginView,ProfileView,UserChangePassordView,SendPasswordRestEmailView,UserResetPasswordView

urlpatterns = [
    path('register/', UserRegistrationView.as_view(),name='register'), 
    path('login/', LoginView.as_view(),name='login'), 
    path('profile/', ProfileView.as_view(),name='profile'), 
    path('changepassword/', UserChangePassordView.as_view(),name='changepassword'), 
    path('RestPassword/', SendPasswordRestEmailView.as_view(),name='RestPassword'), 
    path('RestPasswordView/<uid>/<token>/', UserResetPasswordView.as_view(),name='RestPasswordView'),
   
]
