from django.urls import reverse
from rest_framework.test import APITestCase, APIClient
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile

from cloude_app.models import UserFile

User = get_user_model()

class BaseAPITestCase(APITestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_superuser(
            login='testuser',
            email='test@example.com',
            password='testpass123'
        )
        
        auth_response = self.client.post('/api/token/', {
            'login': 'testuser',
            'password': 'testpass123'
        })
        
        self.assertEqual(auth_response.status_code, 200)
        token = auth_response.data['access']
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')

class TestFileCreation(BaseAPITestCase):
    def test_simple_file_create(self):
        url = reverse('files-list')
        file = SimpleUploadedFile(
            name='test.txt',
            content=b'Hello World',
            content_type='text/plain'
        )
        
        data = {
            'file': file,
            'comment': 'тест'
        }
        
        response = self.client.post(url, data, format='multipart')
        self.assertEqual(response.status_code, 201)

class TestFileList(BaseAPITestCase):
    def test_get_file_list(self):
        url = reverse('files-list')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

class TestAuth(BaseAPITestCase):
    def test_login(self):
        response = self.client.post('/api/token/', {
            'login': 'testuser',
            'password': 'testpass123'
        })
        self.assertEqual(response.status_code, 200)
        self.assertIn('access', response.data)

class TestFileDelete(BaseAPITestCase):
    def setUp(self):
        super().setUp()
        self.file = UserFile.objects.create(
            user=self.user,
            file=SimpleUploadedFile(
                name='test.txt',
                content=b'Test content',
                content_type='text/plain'
            ),
            comment='Test'
        )
    
    def test_delete_file(self):
        url = reverse('delete-file', kwargs={'pk': self.file.pk})
        response = self.client.delete(url)
        self.assertEqual(response.status_code, 204)

