
import mimetypes
from django.http import HttpResponse
from .models import User, UserFile, FileShareLink
from .serializers import CustomTokenObtainPairSerializer, RegisterSerializer, UserSerializer, UserFileSerializer
from rest_framework import viewsets, status, generics
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.response import Response
from rest_framework import viewsets, permissions, status
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from rest_framework.views import APIView
from django.shortcuts import get_object_or_404
import os
import uuid
from django.utils import timezone

class UsersViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    
class UserDetailView(generics.RetrieveAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    lookup_field = 'id'

class UserFileViewSet(viewsets.ModelViewSet):
    queryset = UserFile.objects.all()
    serializer_class = UserFileSerializer
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser, JSONParser]  # Парсеры для файлов

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    def get_queryset(self):
        # Это только файлы текущего пользователя
        return UserFile.objects.filter(user=self.request.user)
    
    
    

class MyTokenObtainPairView(TokenObtainPairView):
    permission_classes = [AllowAny]
    serializer_class = CustomTokenObtainPairSerializer
  
class DownloadFileView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, pk):
        try:
            file_obj = get_object_or_404(UserFile, pk=pk)
            file_path = file_obj.file.path
            
            if not os.path.exists(file_path):
                return Response({'error': 'Файл не найден'}, status=404)
            
            filename = os.path.basename(file_obj.file.name)
            content_type = mimetypes.guess_type(file_path)[0] or 'application/octet-stream'
            
            with open(file_path, 'rb') as fh:
                response = HttpResponse(fh.read(), content_type=content_type)
                response['Content-Disposition'] = f'attachment; filename="{filename}"'
                return response
            
        except FileNotFoundError:
            return Response({'error': 'Файл не найден'}, status=404)
        except Exception as e:
            return Response({'error': str(e)}, status=500)
    
class DeleteFileView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def delete(self, request, pk):
       
        file_obj = get_object_or_404(UserFile, pk=pk, user=request.user)
        if file_obj.file:
            file_obj.file.delete()
        file_obj.delete()
        
        return Response({'message': 'Файл удален'}, status=204)
        

class RegisterViewSet(viewsets.GenericViewSet):
    permission_classes = [AllowAny]
    serializer_class = RegisterSerializer
    
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        
        refresh = RefreshToken.for_user(user)
        tokens = {
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }
        
        return Response({
            'user': {
                'id': user.id,
                'login': user.login,
                'email': user.email
            },
            'tokens': tokens
        }, status=status.HTTP_201_CREATED)
    
class CreateShareLinkView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        file_id = request.data.get('file-id')
        
        try:
            file = UserFile.objects.get(id=file_id, user=request.user)
            
            token = uuid.uuid4()
            expires_at = timezone.now() + timezone.timedelta(days=7)  # Срок действия
            
            link = FileShareLink.objects.create(
                file=file,
                token=token,
                expires_at=expires_at
            )
            print(link)
            base_url = request.build_absolute_uri('/api/download-public/')
            share_url = f"{base_url}{link.token}"
            
            return Response({'share_url': share_url}, status=status.HTTP_201_CREATED)
        
        except UserFile.DoesNotExist:
            return Response({'error': 'Файл не найден'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class PublicDownloadView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, token):
        try:
            link = FileShareLink.objects.get(token=token)
            
            if link.is_expired():
                return Response({'error': 'Срок действия ссылки истёк'}, status=status.HTTP_400_BAD_REQUEST)
            
            file_path = link.file.file.path
            filename = os.path.basename(link.file.file.name)
            
            content_type = mimetypes.guess_type(file_path)[0] or 'application/octet-stream'
            
            with open(file_path, 'rb') as fh:
                response = HttpResponse(fh.read(), content_type=content_type)
                response['Content-Disposition'] = f'attachment; filename="{filename}"'
                return response
            
        except FileShareLink.DoesNotExist:
            return Response({'error': 'Неверная ссылка'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    