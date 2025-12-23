from django.test import TestCase
from django.utils import timezone
from django.core.exceptions import ValidationError
from datetime import timedelta
from django.core.files.uploadedfile import SimpleUploadedFile

from cloude_app.models import FileShareLink, User, UserFile

class FileShareLinkTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            login='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.test_file = UserFile.objects.create(
            user=self.user,
            file=SimpleUploadedFile(
                name='test.txt',
                content=b'Test content',
                content_type='text/plain'
            )
        )

    def test_invalid_expires_at(self):
        with self.assertRaises(ValidationError):
            FileShareLink.objects.create(
                file=self.test_file,
                expires_at=timezone.now() - timedelta(days=1)
            )

    def test_valid_expires_at(self):
        FileShareLink.objects.create(
            file=self.test_file,
            expires_at=timezone.now() + timedelta(days=1)
        )