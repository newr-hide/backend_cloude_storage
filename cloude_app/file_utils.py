import os
from django.http import Http404
from rest_framework.exceptions import APIException
from .models import  UserFile

class FileSystemUtils:
    def __init__(self, user=None, request=None):
        self.user = user
        self.request = request
    def get_file_by_id(self, file_id):
        try:
            return UserFile.objects.get(id=file_id, user=self.user)
        except UserFile.DoesNotExist:
            raise Http404("Файл не найден")

    def download_file(self, file_obj):
        print('start downl')
        try:
            file_path = file_obj.file.path
            print(file_path)
            if not os.path.exists(file_path):
                raise Http404("Файл не найден")
            return file_path, file_obj.original_name
        except Exception as e:
            raise APIException(f"Ошибка при загрузке файла: {str(e)}")
