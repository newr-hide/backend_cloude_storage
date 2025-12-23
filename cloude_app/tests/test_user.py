from django.test import TestCase
from cloude_app.models import User


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