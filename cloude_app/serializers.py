import os
import re
from rest_framework import serializers
from .models import User, UserFile
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
import logging
from django.db.models import Sum
from django.core.validators import validate_email

User = get_user_model()
logger = logging.getLogger(__name__)


class UserSerializer(serializers.ModelSerializer):
    total_files = serializers.SerializerMethodField()
    total_size = serializers.SerializerMethodField()
    
    def get_total_files(self, obj):
        return UserFile.objects.filter(user=obj).count()
    
    def get_total_size(self, obj):
        files = UserFile.objects.filter(user=obj)
        total_size = files.aggregate(total=Sum('file_size'))['total'] or 0
        return total_size
    
    def get_fields(self):
        fields = super().get_fields()
        
        try:
            request = self.context.get('request')
            if request and request.user.is_authenticated:
                if not request.user.is_admin: 
                    fields.pop('is_active', None)
                    fields.pop('is_admin', None)
            else:
                logger.warning("Запрос без аутентификации или контекста")
        except Exception as e:
            logger.error(f"Ошибка при проверке прав: {str(e)}")
        
        return fields
    class Meta:
        model = User
        fields = ['id','login', 'email', 'is_active', 'is_admin', 'date_joined','total_files', 'total_size']
        read_only_fields = ['date_joined']

class UserFileSerializer(serializers.ModelSerializer):
    file_size = serializers.SerializerMethodField()
    
    def get_file_size(self, obj):
        try:
            return obj.file_size
        except:
            return 0
        
    last_downloaded = serializers.DateTimeField(
        format='%d-%m-%Y',
        read_only=True
    )
    
    class Meta:
        model = UserFile
        fields = [
            'id',
            'original_name',
            'file',
            'comment',
            'user',
            'uploaded_at',
            'file_size',
            'last_downloaded'
        ]
        read_only_fields = ['user', 'uploaded_at', 'file_size']

    def create(self, validated_data):
        try:
            file = validated_data.pop('file', None)
            if not file:
                raise serializers.ValidationError({'file': 'Файл обязателен'})
            
            instance = UserFile(
                file=file,
                original_name=os.path.basename(file.name),
                file_size=file.size,
                comment=validated_data.get('comment', ''),
                user=self.context['request'].user
            )
            
            instance.save()
            return instance
        except Exception as e:
            logger.error(f"Ошибка при загрузке файла: {str(e)}", exc_info=True)
            print(f"Ошибка при создании: {str(e)}")
            raise serializers.ValidationError(str(e))

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['user_id'] = user.id
        token['login'] = user.login
        token['email'] = user.email
        token['is_admin'] = user.is_admin
        return token

    def validate(self, attrs):
        data = super().validate(attrs)
        refresh = self.get_token(self.user)
        data['refresh'] = str(refresh)
        data['access'] = str(refresh.access_token)
        data['user'] = {
            'id': self.user.id,
            'login': self.user.login,
            'email': self.user.email,
            'is_admin': self.user.is_admin
        }
        return data

    
class CustomTokenRefreshSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    def validate(self, attrs):
        logger.info("Начало процесса обновления токена")
        
        try:
            refresh = RefreshToken(attrs['refresh'])
            user_id = refresh['user_id']

            try:
                user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                raise serializers.ValidationError({'detail': 'Пользователь не найден'})
            data = {
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }
            
            data['user'] = {
                'id': user.id,
                'login': user.login,
                'email': user.email,
                'is_admin': user.is_admin,
                'is_active': user.is_active,
            }

            logger.info("Токен успешно обновлен")
            return data
        
        except TokenError as e:
            logger.error(f"Ошибка токена: {str(e)}")
            raise serializers.ValidationError({'detail': str(e)})
        
        except Exception as e:
            logger.error(f"Ошибка при обновлении токена: {str(e)}")
            raise

    
class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True, 
        required=True, 
        style={'input_type': 'password'}
    )
    
    class Meta:
        model = User
        fields = ['login', 'email', 'password']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def validate_login(self, value):
        if not value[0].isalpha():
            raise serializers.ValidationError("Первый символ логина должен быть буквой")
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9]*$', value):
            raise serializers.ValidationError("Логин может содержать только латинские буквы и цифры")
        if len(value) < 4 or len(value) > 20:
            raise serializers.ValidationError("Длина логина должна быть от 4 до 20 символов")
        return value
    
    def validate_password(self, value):
        try:
            validate_password(value)
        except ValidationError as e:
            raise serializers.ValidationError(e.messages)
        if len(value) < 6:
            raise serializers.ValidationError("Пароль должен содержать минимально 6 смволов")
        if not any(char.isupper() for char in value):
            raise serializers.ValidationError("Пароль должен содержать хотябы одну заглавную букву")
        if not any(char.isdigit() for char in value):
            raise serializers.ValidationError("Пароль должен содержать хотя бы одну цифру")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', value):
            raise serializers.ValidationError("Пароль должен содержать специальный символ")
        return value
    
    def validate_email(self, value):
        try:
            validate_email(value)
        except ValidationError:
            raise serializers.ValidationError("Некорректный формат email")

        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Пользователь с таким email уже существует")
            
        return value

    def create(self, validated_data):
        try:
            user = User.objects.create_user(
                login=validated_data['login'],
                email=validated_data['email'],
                password=validated_data['password']  
            )
            return user
        except Exception as e:
            raise serializers.ValidationError(str(e))