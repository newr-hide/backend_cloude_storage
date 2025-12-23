import os
import uuid
from cloude_app.models import FileShareLink, UserFile
from django.utils import timezone
from rest_framework.exceptions import APIException
import logging
logger = logging.getLogger(__name__)

class BaseService:
    def __init__(self, user=None):
        self.user = user

class FileService(BaseService):
    def __init__(self, user=None, request=None):
        super().__init__(user=user)
        self.request = request  

    def get_queryset(self):
        queryset = UserFile.objects.all()
        user_id = self.request.query_params.get('user_id') if self.request else None
        
        if self.user.is_admin:
            if user_id:
                return queryset.filter(user_id=user_id)
            return queryset
        return queryset.filter(user=self.user)
    
    def get_file_by_id(self, file_id):
        try:
            return UserFile.objects.get(id=file_id, user=self.user)
        except UserFile.DoesNotExist:
            raise FileNotFoundError("Файл не найден")
    
    def delete_file(self, file_obj):
        try:
            file_obj.delete()
        except Exception as e:
            raise APIException(f"Ошибка при удалении файла: {str(e)}")
    
    def create_share_link(self, file_obj):
        try:
            token = uuid.uuid4()
            expires_at = timezone.now() + timezone.timedelta(days=7)
            return FileShareLink.objects.create(
                file=file_obj,
                token=token,
                expires_at=expires_at
            )
        except Exception as e:
            raise APIException(f"Ошибка при создании ссылки: {str(e)}")
    
    def download_file(self, file_obj):
        try:
            file_path = file_obj.file.path
            if not os.path.exists(file_path):
                raise FileNotFoundError("Файл не найден")
            return file_path, file_obj.original_name
        except Exception as e:
            raise APIException(f"Ошибка при загрузке файла: {str(e)}")
        
    def create_file(self, validated_data):
        try:
            return UserFile.objects.create(user=self.user, **validated_data)
        except Exception as e:
            logger.error(f"Ошибка при создании файла: {str(e)}", exc_info=True)
            raise 
        
    def update_file(self, instance, validated_data):
        try:
            self._check_permissions(instance)
            cleaned_data = self._clean_data(validated_data)
            
            for attr, value in cleaned_data.items():
                setattr(instance, attr, value)
            
            instance.save()
            return instance
        except Exception as e:
            raise APIException(f"Ошибка при обновлении файла: {str(e)}", code=500)

    def update_last_downloaded(self, instance):
        try:
            self._check_permissions(instance)
            instance.last_downloaded = timezone.now()
            instance.save()
            return instance
        except Exception as e:
            raise APIException(f"Ошибка при обновлении даты скачивания: {str(e)}", code=500)

    def _check_permissions(self, instance):
        if not self.user.is_admin and instance.user != self.user:
            raise PermissionError("Доступ запрещен")

    def _clean_data(self, data):
        allowed_fields = ['original_name', 'comment']
        cleaned_data = {
            attr: value 
            for attr, value in data.items() 
            if attr in allowed_fields
        }
        
        if 'file' in cleaned_data:
            if cleaned_data['file'] is None or not cleaned_data['file']:
                cleaned_data.pop('file')
        
        return cleaned_data