import os
import uuid
from cloude_app.models import FileShareLink, UserFile
from django.utils import timezone
from rest_framework.exceptions import APIException
import logging
logger = logging.getLogger(__name__)
from rest_framework import status

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
        
    def create_file(self, validated_data):
        try:
            return UserFile.objects.create(user=self.user, **validated_data)
        except Exception as e:
            logger.error(f"Ошибка при создании файла: {str(e)}", exc_info=True)
            raise 
        
    def _clean_data(self, validated_data):
        allowed_fields = ['original_name', 'comment']
        return {k: v for k, v in validated_data.items() if k in allowed_fields}

    def update_file(self, instance, validated_data):
        try:
            cleaned_data = self._clean_data(validated_data)
            if not cleaned_data:
                raise APIException("Нет данных для обновления", code=status.HTTP_400_BAD_REQUEST)

            for attr, value in cleaned_data.items():
                setattr(instance, attr, value)

            instance.save()
            return instance

        except APIException as e:
            raise e

        except Exception as e:
            raise APIException(
                detail=f"Ошибка при обновлении файла: {str(e)}",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def update_last_downloaded(self, instance):
        try:
            instance.last_downloaded = timezone.now()
            instance.save()
            return instance
        except Exception as e:
            raise APIException(f"Ошибка при обновлении даты скачивания: {str(e)}", code=status.HTTP_500_INTERNAL_SERVER_ERROR)




