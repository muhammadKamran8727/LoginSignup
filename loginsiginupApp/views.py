from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from .serializers import UserRegistrationSerializer,UserLoginSerializer,ProfileSerilizer,UserChangePasswordSerializer,SendPasswordRestEmailSerializer,UserResetPasswordSerializer
from django.contrib.auth import authenticate
from loginsiginupApp.renderer import UserRenderer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated


def get_tokens_for_user(user):
  refresh = RefreshToken.for_user(user)

  return {
      'refresh': str(refresh),
      'access': str(refresh.access_token),
  }
# Create your views here.


class UserRegistrationView((APIView)):
  renderer_classes=[UserRenderer]
  def post(self, request, format=None):
    serializer=UserRegistrationSerializer(data=request.data)
    if serializer.is_valid(raise_exception=True):
      user = serializer.save()
      token=get_tokens_for_user(user)
      return Response({'token': token, 'msg':'Registration Successful'}
      ,status=status.HTTP_201_CREATED)
    return Response(serializer.errors
    ,status=status.HTTP_400_BAD_REQUEST)
  

class LoginView(APIView):
  renderer_classes=[UserRenderer]
  def post(self,request,format=None):
    serializer=UserLoginSerializer(data=request.data)
    # it check validation if error raise exception
    if serializer.is_valid(raise_exception=True):
      #This get the email and password from db and then check
      email=serializer.data.get('email') 
      password=serializer.data.get('password')
      #Now we check by this email and password available then aunthicate it other give error
      user=authenticate(email=email,password=password)
      if user is not None:
        token=get_tokens_for_user(user)
        return Response({'token': token,'msg':'Login Successfully'},status=status.HTTP_200_OK)
      else:
        return Response({'errrors':{'non_field_errors':['Email and Password is not Valid']}}
        ,status=status.HTTP_404_NOT_FOUND)   
    return Response(serializer.errors
    ,status=status.HTTP_400_BAD_REQUEST)
  

# This is a Profile Get Api
class ProfileView(APIView):
  renderer_classes=[UserRenderer]
  permission_classes=[IsAuthenticated]
  def get(self,request,format=None):
    serializer=ProfileSerilizer(request.user)
    return Response(serializer.data,status=status.HTTP_200_OK)
      


# This Code for Change Password
class UserChangePassordView(APIView):
  renderer_classes=[UserRenderer]
  permission_classes=[IsAuthenticated]
  def post(self,request,format=None):
    serializer=UserChangePasswordSerializer(data=request.data,context={'user':request.user} )
    if serializer.is_valid(raise_exception=True):
      return Response({'msg':'Password Changed Successfully'},status=status.HTTP_200_OK)
    return Response(serializer.errors
    ,status=status.HTTP_400_BAD_REQUEST)
    

#Reset Password View which send email to rest password

class SendPasswordRestEmailView(APIView):
  renderer_classes=[UserRenderer]
  def post(self,request,format=None):
    serializer=SendPasswordRestEmailSerializer(data=request.data)
    if serializer.is_valid(raise_exception=True):
      return Response({'msg':'Password Rest link sended.Please! Check your Emailbox'},status=status.HTTP_200_OK)
    return Response(serializer.errors
    ,status=status.HTTP_400_BAD_REQUEST)
  
  # clicking on link then this view work to set new password

class UserResetPasswordView(APIView):
  renderer_classes=[UserRenderer]
  def post(self, request, uid, token, format=None):      
    serializer = UserResetPasswordSerializer(data=request.data
    ,context={'uid': uid, 'token': token})
    if serializer.is_valid(raise_exception=True):
      return Response({'msg':'Password Rest Successfully'},status=status.HTTP_200_OK)
    return Response(serializer.errors
    ,status=status.HTTP_400_BAD_REQUEST)


