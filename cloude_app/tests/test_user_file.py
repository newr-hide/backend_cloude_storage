from django.core.files.uploadedfile import SimpleUploadedFile
import tempfile
import os

from django.test import TestCase

from cloude_app.models import User, UserFile

class UserFileTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            login='testuser',
            email='test@example.com'
        )
        self.temp_file = tempfile.NamedTemporaryFile(delete=False)
        self.temp_file.write(b'Test file content')
        self.temp_file.flush()

    def tearDown(self):
        try:
            os.remove(self.temp_file.name)
        except:
            pass

    def test_file_creation(self):
        file = UserFile.objects.create(
            user=self.user,
            file=SimpleUploadedFile(
                name='test.txt',
                content=b'Test content',
                content_type='text/plain'
            )
        )
        
        self.assertEqual(file.original_name, 'test.txt')
        self.assertEqual(file.file_size, 12)  # Длина строки 'Test content'

    def test_download_method(self):
        file = UserFile.objects.create(
            user=self.user,
            file=SimpleUploadedFile(
                name='test.txt',
                content=b'Test content',
                content_type='text/plain'
            )
        )
        
        self.assertIsNone(file.last_downloaded)
        file.download()
        self.assertIsNotNone(file.last_downloaded)