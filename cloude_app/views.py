from django.shortcuts import render
from django.http import HttpResponse
from .models import User, UserFile
from .serializers import UserSerializer, UserFileSerializer
from rest_framework.permissions import IsAuthenticated
from rest_framework import viewsets,permissions
from rest_framework.decorators import action
def index(request):
    context = {
        'title': 'Home',
        'content': 'Главная страница приложения'
    }
    return render(request, 'index.html', context)

def about(request):
    return HttpResponse('About page')

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    
class UserFileViewSet(viewsets.ModelViewSet):
    queryset = UserFile.objects.all()
    serializer_class = UserFileSerializer