from django.forms import ValidationError
from django.test import TestCase
from cloude_app.models import User

from django.db import DataError, IntegrityError


class UserModelTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            login='testuser',
            email='test@example.com',
            password='testpass123'
        )

    def test_str_representation(self):
        self.assertEqual(str(self.user), 'testuser')

    def test_is_staff_property(self):
        self.assertFalse(self.user.is_staff)
        self.user.is_admin = True
        self.assertTrue(self.user.is_staff)


class TestUserEdgeCases(TestCase):
    def test_unique_login(self):

        User.objects.create_user(
            login='testuser',
            email='test@example.com',
            password='password123'
        )
        
        with self.assertRaises(IntegrityError):
            User.objects.create_user(
                login='testuser',
                email='another@example.com',
                password='password123'
            )
            
    def test_unique_email(self):
        User.objects.create_user(
            login='testuser',
            email='test@example.com',
            password='password123'
        )
        
        with self.assertRaises(IntegrityError):
            User.objects.create_user(
                login='anotheruser',
                email='test@example.com',
                password='password123'
            )
            
    def test_max_login_length(self):
        max_length_login = 'a' * 30 
        User.objects.create_user(
            login=max_length_login,
            email='test@example.com',
            password='password123'
        )
        
        with self.assertRaises(DataError):
            too_long_login = 'a' * 31
            User.objects.create_user(
                login=too_long_login,
                email='test@example.com',
                password='password123'
            )
            
            
    def test_empty_login(self):
        with self.assertRaises(ValueError):
            User.objects.create_user(
                login='',
                email='test@example.com',
                password='password123'
            )
            
    def test_empty_email(self):
        with self.assertRaises(ValueError):
            User.objects.create_user(
                login='testuser',
                email='',
                password='password123'
            )