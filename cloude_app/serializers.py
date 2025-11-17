from rest_framework import serializers
from .models import User, UserFile

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id','login', 'email']

class UserFileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserFile
        fields = '__all__'