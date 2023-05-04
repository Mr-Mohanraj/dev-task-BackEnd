import string
import random

# django package imports
from django.shortcuts import get_object_or_404
from rest_framework import status
from django.core.mail import send_mail
from django.contrib.auth import login, logout

# django rest framework imports
from rest_framework.views import APIView
from rest_framework.views import Response
from rest_framework import exceptions
from rest_framework import authentication, permissions

# apps package import
from authenticationApi.utils import (
    create_access_token, decode_access_token, create_refresh_token, decode_refresh_token)
from authenticationApi.authentication import JWTAuthentication
from .models import User, Reset
from .serializers import UserSerializer, LoginSerializer, ForgotSerializer, ResetSerializer
from .utils import isValidEmail


class SignUpApiView(APIView):
    """
    Info:
        * Signup view for create a new account.

    Required Field:
        * username : String
        * email : String
        * password : String
        * password_confirm : string (same as a password)

    Response: Json
        {
        id: Integer,
        email: String,
        username: String
        }
    """
    serializer_class = UserSerializer
    permission_classes = []
    authentication_classes = []

    def post(self, request):
        data = request.data
        try:
            if not isValidEmail(data['email']):
                raise exceptions.APIException(
                    'Please enter valid email address.')
                
            if data['password'] != data['password_confirm']:
                raise exceptions.APIException('Password do not match!')
            serializer = UserSerializer(data=data)
            serializer.is_valid(raise_exception=True)
            serializer.save()
        except Exception as e:
            return Response({"error": str(e)}, status.HTTP_400_BAD_REQUEST)
        return Response(serializer.data, status.HTTP_201_CREATED)


class SignInApiView(APIView):
    """
    Info:
        * Login view for signup user to sign-in into the account.

    Required Field:
        * email : String
        * password : String

    Response : Json
        {
        token : String (Token)
        }

    """
    serializer_class = LoginSerializer
    permission_classes = []
    authentication_classes = []

    def post(self, request):
        try:
            email = request.data['email']
            password = request.data['password']
        except:
            return Response({"msg": "please enter your email and password or create a account <a href=''>register</a>"}, status.HTTP_204_NO_CONTENT)

        if not isValidEmail(email):
            raise exceptions.AuthenticationFailed(
                'Enter a valid email address.')

        try:
            user = User.objects.filter(email=email).first()
        except:
            return Response({"msg": "email is does not exits"}, status.HTTP_204_NO_CONTENT)

        if user is None:
            raise exceptions.AuthenticationFailed('user does not exits')

        if not user.check_password(password):
            raise exceptions.AuthenticationFailed('password does not match')

        access_token = create_access_token(user.id)
        user.token = access_token
        user.save()
        refresh_token = create_refresh_token(user.id)
        login(request, user)
        response = Response()

        response.set_cookie(key='refresh_token',
                            value=refresh_token, httponly=True)
        response.data = {
            'token': access_token
        }
        response.status_code = status.HTTP_200_OK

        return response


class UserApiView(APIView):
    """
    Info:
        * User view for sign-in user to see an our own user information's.

    Required Field :
        * token : String (Token)

    Response : Json
        {
        id: integer
        username: String
        }
    """

    authentication_classes = [JWTAuthentication]
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        return Response(UserSerializer(request.user).data, status.HTTP_200_OK)


class RefreshTokenAPIView(APIView):
    """
    Info:
        * Refresh Token view for sign-in user to refresh the old token to new one. just use the api path user/refresh/.
        * But user must be authorized otherwise the endpoints not working.

    Required Field :
        * token: String (Token)

    Response : Json
        {
        token : String (Token)
        }

    """

    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        refresh_token = request.COOKIES.get('refresh_token')
        id = decode_refresh_token(refresh_token)
        access_token = create_access_token(id)
        refresh_token = create_refresh_token(id)

        try:
            user = get_object_or_404(User, pk=id)
            if not (user.token == 0):
                user.token = access_token
                user.save()
                response = Response()
                response.set_cookie(key="refresh_token",
                                    value=refresh_token, httponly=True)
                response.data = {
                    'token': access_token
                }
                response.status_code = status.HTTP_200_OK
                return response
            return Response({"msg": "Please login again your refresh token is does not exits"}, status.HTTP_204_NO_CONTENT)
        except:
            return Response({"msg": "Please login again your refresh token is does not match"}, status.HTTP_204_NO_CONTENT)


class ForgetAPIView(APIView):
    """
    Info:
        * Forgot view for sign-in user to forget password method or change the old without know the old password

    Required Field :
        * email: String (must be signup email)

    Response : Json
        {
        msg: String 
        }

    """
    serializer_class = ForgotSerializer
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def post(self, request):
        try:
            email = request.data['email']
        except:
            return Response({"msg": "Enter your login email address"}, status.HTTP_404_NOT_FOUND)
        token = ''.join(random.choice(string.ascii_lowercase +
                        string.digits) for _ in range(10))
        
        if not isValidEmail(email):
            raise exceptions.AuthenticationFailed('Enter a valid email address.')
        
        Reset.objects.create(
            email=email,
            token=token
        )
        url = request.build_absolute_uri('/')
        url = f'{url}api/user/reset/{token}'

        send_mail(
            subject='Reset your password',
            message='Click <a href="%s">here</a> to ree your password' % url,
            from_email='from_mail@gmail.com',
            recipient_list=[email]
        )

        return Response({
            'message': f'success and url send to the your {email} address. your mail"s are send to the server is running (terminal or console)'
        }, status.HTTP_200_OK)


class ResetAPIView(APIView):
    """
    Info:
        * Reset view for sign-in user to change the user old password to new password.
        * Here the Temporary Token for only reset the password. After change the password the token is automatically delete.

    Required Field :
        password: String
        password_confirm: String

    Response : Json
        {
            msg: String
        }

    """
    serializer_class = ResetSerializer
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def post(self, request, token):
        data = request.data
        try:
            if data['password'] != data['password_confirm']:
                raise exceptions.APIException('Passwords do not match')
        except KeyError:
            return Response("Please enter the new_password and password_confirm")

        try:
            reset = Reset.objects.filter(token=token).first()
            user = get_object_or_404(User, email=reset.email)
        except:
            return Response({"msg": "your get token email is not register email, please get reset token as register email"}, status.HTTP_204_NO_CONTENT)

        if not user:
            raise exceptions.APIException('Invalid link!')

        user.set_password(data['password'])
        user.token = 0
        user.save()
        reset.delete()
        logout(request)
        response = Response()

        response.delete_cookie(key="refresh_token")
        response.data = {
            'message': 'success, Please Login again'
        }
        response.status_code = status.HTTP_205_RESET_CONTENT
        return response


class SignOutApiView(APIView):
    """
    Info:
        * SignOut view for SignOut the exiting a account.

    Required Field:
        * token : String (Token)

    response : Json
        {
        msg: String
        }
    """
    # serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]
    authentication_classes = [JWTAuthentication]

    def post(self, request):
        refresh_token = request.COOKIES.get('refresh_token')
        id = decode_refresh_token(refresh_token)
        try:
            user = get_object_or_404(User, pk=id)
            user.token = 0
            user.save()
        except:
            return Response({"msg": "Please login again your refresh token is does not match"})
        response = Response()

        response.delete_cookie(key="refresh_token")

        response.data = {
            "msg": "logout successfully! Welcome back Sir :)"
        }
        response.status_code = status.HTTP_200_OK

        return response
