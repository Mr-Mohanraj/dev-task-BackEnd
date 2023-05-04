from rest_framework import exceptions
from rest_framework.authentication import BaseAuthentication
from rest_framework.authentication import get_authorization_header
from .models import User
from .utils import decode_access_token
from drf_spectacular.contrib.rest_framework_simplejwt import SimpleJWTScheme


class JWTAuthentication(BaseAuthentication):
    """Use to find the user is already register or not. based on the token in cookies inside the browsers"""

    def authenticate(self, request):
        auth = get_authorization_header(request=request).split()

        if auth and len(auth) == 2:
            token = auth[1].decode('utf-8')
            id = decode_access_token(token)

            user = User.objects.get(pk=id)

            return (user, None)

        raise exceptions.AuthenticationFailed('Unauthenticated')


class SimpleJWTTokenUserScheme(SimpleJWTScheme):
    name = "CustomJWTAuth"
    target_class = JWTAuthentication
