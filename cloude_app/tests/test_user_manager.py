from django.test import TestCase
from django.core.exceptions import ValidationError
from cloude_app.models import User

class UserManagerTestCase(TestCase):
    def setUp(self):
        self.manager = User.objects

    def test_create_user(self):
        user = self.manager.create_user(
            login='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.assertEqual(user.login, 'testuser')
        self.assertEqual(user.email, 'test@example.com')
        self.assertFalse(user.is_admin)
        self.assertFalse(user.is_superuser)

    def test_create_superuser(self):
        superuser = self.manager.create_superuser(
            login='superuser',
            email='super@example.com',
            password='superpass123'
        )
        self.assertTrue(superuser.is_admin)
        self.assertTrue(superuser.is_superuser)
        self.assertTrue(superuser.is_active)


class TestUserManagerEdgeCases(TestCase):
    def test_create_user_with_empty_login(self):
        with self.assertRaises(ValueError):
            User.objects.create_user(
                login='',
                email='test@example.com',
                password='password123'
            )
            
    def test_create_user_with_empty_email(self):
        with self.assertRaises(ValueError):
            User.objects.create_user(
                login='testuser',
                email='',
                password='password123'
            )
            
