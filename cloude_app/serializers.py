from rest_framework import serializers
from .models import User, UserFile
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth import get_user_model

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id','login', 'email']

class UserFileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserFile
        fields = '__all__'


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
                'email': getattr(self.user, 'email', None)
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

    def validate_password(self, value):
        try:
            validate_password(value)
        except ValidationError as e:
            raise serializers.ValidationError(e.messages)
        return value

    

    def create(self, validated_data):
        
        user = User.objects.create_user(
            login=validated_data['login'],
            email=validated_data['email'],
            password=validated_data['password']  
        )
        return user