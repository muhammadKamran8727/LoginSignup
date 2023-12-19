from ctypes import util
from rest_framework import serializers
from .models import User
from django.utils.encoding import force_bytes
from django.utils.encoding import smart_str, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator 
from rest_framework.exceptions import ValidationError
from .utils import Util


class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(style={'input_type':'password'}
    ,write_only=True)
    password2 = serializers.CharField(style={'input_type':'password'}
    ,write_only=True)
    class Meta:
      model = User
      fields=['email','name','password','password2','tc']
      extra_kwargs={
        'password':{'write_only':True}
      }

# Validation for PAssword and Confirm Password      
    def validate(self, attrs):
      password = attrs.get('password')
      password2 = attrs.get('password2')

      if password != password2:
        raise serializers.ValidationError("Password and confirm password don't match")

      return attrs
    
    def create(self,Validate_data):
      return User.objects.create_user(**Validate_data)
    

# User LoginSerializer Class
 
class UserLoginSerializer(serializers.ModelSerializer):
  email=serializers.EmailField(max_length=255)
  password=serializers.CharField(max_length=100)

  class Meta:
    model=User
    fields=['email','password']


#Profile View Get Serializer

class ProfileSerilizer(serializers.ModelSerializer):
  class Meta:
    model=User
    fields=['id','email','name']

#Password change Serializer
    
class UserChangePasswordSerializer(serializers.ModelSerializer):
  password = serializers.CharField(style={'input_type':'password'}
  ,write_only=True)
  password2 = serializers.CharField(style={'input_type':'password2'}
  ,write_only=True)
  
  class Meta:   
    model=User
    fields=['password','password2']

  def validate(self, attrs):
      password = attrs.get('password')
      password2 = attrs.get('password2')
      user=self.context.get('user')   
      if password != password2:
        raise serializers.ValidationError("Password and confirm password don't match")
      user.set_password(password)
      user.save()

      return attrs
  

class SendPasswordRestEmailSerializer(serializers.ModelSerializer):
  email=serializers.EmailField(max_length=255)
  
  class Meta:
    model=User
    fields=['email']

  def validate(self,attrs):
    email=attrs.get('email')
    if User.objects.filter(email=email).exists():
      user=User.objects.get(email=email)
      uid=urlsafe_base64_encode(force_bytes(user.id))
      print('Encode UID', uid)
      token=PasswordResetTokenGenerator().make_token(user)
      print('Password Rest Token',token)
      link='http://localhost:3000/api/user/reset'+uid+'/'+token
      print('Password Rest Link',link)
      body='Click following Link to Rest Password'+link
      data={
        'subject':'Rest Your Password',
        'body':body,
        'to_email':user.email,
      }
      Util.send_email(data)


      return attrs     
    else:
      raise ValidationError("You're not a Register User")

#This is way to change password
    
class UserResetPasswordSerializer(serializers.ModelSerializer):
  password = serializers.CharField(max_length=255, style={'input_type':'password'},write_only=True)
  password2 = serializers.CharField(max_length=255, style={'input_type':'password'},write_only=True)
  class Meta:
    model=User
    fields = ['password','password2']

  def validate(self, attrs):
    try:
      password = attrs.get('password')
      password2 = attrs.get('password2')
      uid = self.context.get('uid')  
      token = self.context.get('token')
      if password != password2:
         raise serializers.ValidationError("Password and Confirm Password does not match")
      id = smart_str(urlsafe_base64_decode(uid))
      user = User.objects.get(id=id)
      if not PasswordResetTokenGenerator().check_token(user, token):
        raise ValidationError("Token is not valid or Expired")
      user.set_password(password)
      user.save()
      return attrs
    except DjangoUnicodeDecodeError as identifier:
      PasswordResetTokenGenerator().check_token(user,token)
      raise ValidationError('Token Expired or Not Valid') 




#This is another way throug we can easily can change password

# class UserResetPasswordSerializer(serializers.ModelSerializer):
#   password = serializers.CharField(style={'input_type': 'password'}, write_only=True)
#   password2 = serializers.CharField(style={'input_type': 'password2'}, write_only=True)
#   class Meta:
#     model = User
#     fields = ['password', 'password2']
#   def validate(self, attrs):
#     try:
#       password = attrs.get('password')
#       password2 = attrs.get('password2')
#       uid = self.context.get('uid') 
#       token = self.context.get('token')
#       if password != password2:           
#         raise serializers.ValidationError("Password and confirm password don't match")      
#       id_bytes = urlsafe_base64_decode(uid)
#       id_str = force_bytes(id_bytes)
#       id_integer = int(id_str) 
#       user = User.objects.get(id=id_integer)
#       if not PasswordResetTokenGenerator().check_token(user, token):
#         raise ValidationError('Token Expired or Not Valid')
#       user.set_password(password)
#       user.save()
#       return attrs
#     except (TypeError, ValueError, User.DoesNotExist, DjangoUnicodeDecodeError):
#       raise serializers.ValidationError('Token Expired or Not Valid')













