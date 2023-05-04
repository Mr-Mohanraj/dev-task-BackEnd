"""
Tests for the user API.
"""
from django.test import TestCase
from django.contrib.auth import get_user_model
from django.urls import reverse

from rest_framework.test import APIClient
from rest_framework import status
from .models import ApiAccessToken, User

# CREATE_USER_URL = reverse('user:create')
# TOKEN_URL = reverse('user:token')
# ME_URL = reverse('user:me')


def create_user(**params):
    """Create and return a new user."""
    return User.objects.create_user(**params)


class PublicUserApiTests(TestCase):
    """Test the public features of the user API."""

    def setUp(self):
        self.client = APIClient()

    def test_create_user_success(self):
        """Test creating a user is successful."""
        payload = {
            'email': 'test@example.com',
            'password': 'testpass123',
            'first_name': 'Test Name',
            "last_name": "name",
            "password_confirm":"testpass123"
        }
        res = self.client.post("http://localhost:8000/user/register", payload)
        self.assertEqual(res.status_code, status.HTTP_201_CREATED)
        user = get_user_model().objects.get(email=payload['email'])
        self.assertTrue(user.check_password(payload['password']))
        self.assertNotIn('password', res.data)
