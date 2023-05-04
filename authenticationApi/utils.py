import jwt
import datetime
import re
from rest_framework import exceptions


def isValidEmail(email):
    regex = re.compile(
        r'([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{3,})+')
    if re.fullmatch(regex, email):
        return True
    else:
        return False


def create_access_token(id):
    """
    Info:
        * Create a access token based on the user id or pk
    """
    return jwt.encode({
        'user_id': id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1),
        'iat': datetime.datetime.utcnow()
    }, 'access_secret', algorithm='HS256')


def decode_access_token(token):
    """
    Info:
        * decode a access token to the encode user id
    """

    try:
        payload = jwt.decode(token, 'access_secret', algorithms=['HS256'])

        return payload['user_id']
    except:
        raise exceptions.AuthenticationFailed('Token Unauthenticated')


def create_refresh_token(id):
    """
    Info:
        * Create a refresh token for  activate the access token based on the user id or pk"""

    return jwt.encode({
        'user_id': id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7),
        'iat': datetime.datetime.utcnow()
    }, 'refresh_secret', algorithm='HS256')


def decode_refresh_token(token):
    """
    Info:
        * decode a refresh token to the user id"""

    try:
        payload = jwt.decode(token, 'refresh_secret', algorithms=['HS256'])

        return payload['user_id']
    except:
        raise exceptions.AuthenticationFailed('Token Unauthenticated')
