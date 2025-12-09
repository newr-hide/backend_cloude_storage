import os
import re
from rest_framework import serializers
from .models import User, UserFile
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth import get_user_model


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id','login', 'email', 'is_active', 'is_admin', 'date_joined']
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
        fields = '__all__'
        read_only_fields = ['user', 'original_name', 'uploaded_at', 'file_size']

    def create(self, validated_data):
        try:
            validated_data['user'] = self.context['request'].user
            file_instance = super().create(validated_data)
            file_instance.original_name = os.path.basename(file_instance.file.name)
            file_instance.file_size = file_instance.file.size
            file_instance.save()
            return file_instance
        except Exception as e:
            raise serializers.ValidationError(str(e))
        
      

User = get_user_model()
class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    username_field = User.USERNAME_FIELD 

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        if 'username' in self.fields:
            self.fields.pop('username')
            self.fields[self.username_field] = serializers.CharField(
                required=True,
                help_text='Введите ваш логин',
                label='Логин'
            )
        else:
            self.fields[self.username_field] = serializers.CharField(
                required=True,
                help_text='Введите ваш логин',
                label='Логин'
            )

    def validate(self, attrs):
        
        if self.username_field not in attrs:
            raise serializers.ValidationError({self.username_field: "поле обязательное"})
        if 'password' not in attrs:
            raise serializers.ValidationError({"password": "поле обязательное"})


        data = super().validate(attrs)
        
        try:
            refresh = self.get_token(self.user)
            data['refresh'] = str(refresh)
            data['access'] = str(refresh.access_token)
            
            data['user'] = {
                'id': self.user.id,
                'login': getattr(self.user, 'login', None),
                'email': getattr(self.user, 'email', None),
                'is_admin': getattr(self.user, 'is_admin', None)
            }
            
        except Exception as e:
            raise serializers.ValidationError(f"Ошибка при получении токена: {str(e)}")
        
        return data

    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['id'] = user.id
        token['login'] = user.login
        token['email'] = user.email
        return token
    
    
    
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
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Пользователь с таким Еmail уже существует")
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