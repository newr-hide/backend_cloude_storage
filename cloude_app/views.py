
import mimetypes
from django.http import HttpResponse, StreamingHttpResponse
from .models import User, UserFile, FileShareLink
from .serializers import CustomTokenObtainPairSerializer, RegisterSerializer, UserSerializer, UserFileSerializer
from rest_framework import viewsets, status, generics, filters, mixins
from django_filters.rest_framework import DjangoFilterBackend
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
from rest_framework.exceptions import APIException
from .permissions import IsAdminUser, IsAdminUserOrOwner
import logging
from django.conf import settings
from rest_framework_simplejwt.exceptions import TokenError


logger = logging.getLogger(__name__)


class UsersViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    
class UserDetailView(generics.RetrieveAPIView):
    permission_classes = [IsAdminUserOrOwner]
    queryset = User.objects.all()
    serializer_class = UserSerializer
    lookup_field = 'id'
    def dispatch(self, request, *args, **kwargs):
        token_header = request.META.get('HTTP_AUTHORIZATION')
        # print(f'Token from header: {token_header}')

        jwt_cookie = request.COOKIES.get('access_token')  
        # print(f'JWT Token from Cookie: {jwt_cookie}')

        return super().dispatch(request, *args, **kwargs)


class UserFileViewSet(viewsets.ModelViewSet):
    queryset = UserFile.objects.all()
    serializer_class = UserFileSerializer
    parser_classes = [MultiPartParser, FormParser, JSONParser]  # Парсеры для файлов
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    filterset_fields = ['user', 'uploaded_at'] # фильтры
    search_fields = ['original_name', 'comment']

    def create(self, request, *args, **kwargs):
        # # Начало отладки
        # print("=== Начало ===")
        # print("Метод запроса:", request.method)
        # print("Файл запроса:", request.FILES)
        # print("Данные запроса:", request.data)
        # print("Форма:", request.POST)
        # print("=== Конец ===")

        return super().create(request, *args, **kwargs)
    
    def get_permissions(self):
        if self.action in ['list', 'retrieve', 'destroy']:
            return [IsAdminUser()]
        elif self.action in ['update', 'partial_update']:
            return [IsAdminUserOrOwner()]
        return [permissions.IsAuthenticated()]
        
    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    def get_queryset(self):
        queryset = super().get_queryset()
        
        # Фильтрация по пользователю для админов
        user_id = self.request.query_params.get('user_id')
        if self.request.user.is_admin and user_id:
            return queryset.filter(user_id=user_id)
        
        # Для пользователей только свои файлы
        if not self.request.user.is_admin:
            return queryset.filter(user=self.request.user)
        
        return queryset
    
    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        
        if not request.user.is_admin and instance.user != request.user:
            return Response(status=status.HTTP_403_FORBIDDEN)
        
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(serializer.data)
    
    
class AdminFileFilterView(generics.ListAPIView):
    serializer_class = UserFileSerializer
    permission_classes = [IsAdminUser]
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ['user', 'uploaded_at']
    
    def get_queryset(self):
        user_id = self.kwargs.get('user_id')
        if user_id:
            return UserFile.objects.filter(user_id=user_id)
        return UserFile.objects.all()
        
class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            validated_data = serializer.validated_data 
            
            response = Response(validated_data, status=status.HTTP_200_OK)
            
            response.set_cookie(
                key="access_token",
                value=validated_data["access"],
                max_age=settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'].total_seconds(),
                httponly=True,
                samesite='None',
                secure=True
            )
            
            response.set_cookie(
                key="refresh_token",
                value=validated_data["refresh"],
                max_age=settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'].total_seconds(),
                httponly=True,
                samesite='None',
                secure=True
            )
            
            return response
        
        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )

class RefreshTokenView(APIView):
    authentication_classes = ()  
    permission_classes = ()     

    def post(self, request):
        try:

            refresh_token = request.COOKIES.get('refresh_token')
            if not refresh_token:
                return Response({'error': 'Refresh token not found'}, status=status.HTTP_400_BAD_REQUEST)
            
            refresh = RefreshToken(refresh_token)
            
            user = User.objects.filter(id=refresh['user_id']).first()
            if not user:
                return Response({'error': 'User not found'}, status=status.HTTP_400_BAD_REQUEST)
            
            access = str(refresh.access_token)
            
            response = Response({
                'detail': 'Tokens refreshed successfully',
                'access': access
            }, status=status.HTTP_200_OK)
            
            response.set_cookie(
                key='access_token',
                value=access,
                max_age=settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'].total_seconds(),
                httponly=True,
                samesite='None',
                secure=True
            )
            
            return response
        
        except TokenError as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return Response({'error': 'User does not exist'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': 'Internal server error'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class DownloadFileView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, pk):
        try:
            file_obj = get_object_or_404(UserFile, pk=pk)
            file_path = file_obj.file.path
            file_obj.download()
            
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
        try:
            file_obj = get_object_or_404(UserFile, pk=pk, user=request.user)
            file_obj.delete()
            
            return Response({'message': 'Файл удален'}, status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            raise APIException(f"Ошибка при удалении файла: {str(e)}", code=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

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
            # print(link)
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
        
class AdminUserViewSet(viewsets.GenericViewSet,
                     mixins.ListModelMixin,
                     mixins.DestroyModelMixin):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAdminUser]
    lookup_field = 'id'

    def list(self, request):
        users = self.get_queryset()
        serializer = self.serializer_class(users, many=True)
        return Response(serializer.data)

    def destroy(self, request, id=None):
        print('Запуск')
        try:
            user = self.get_object()
            print(f"Попытка удалить пользователя: {user.login}") 
            user.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            print(f"Ошибка при удалении: {str(e)}") 
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def partial_update(self, request, pk=None):
        user = self.get_object()
        is_admin = request.data.get('is_admin', None)
        
        if is_admin is not None:
            user.is_admin = is_admin
            user.save()
            return Response(self.serializer_class(user).data)
        
        return Response(status=status.HTTP_400_BAD_REQUEST)


class ShowFileView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, pk):
        try:
            file_obj = get_object_or_404(UserFile, pk=pk)
            file_path = file_obj.file.path
            filename = file_obj.original_name or os.path.basename(file_obj.file.name)
            file_extension = os.path.splitext(filename)[1].lower()
            
            content_type = mimetypes.guess_type(file_path)[0] or 'application/octet-stream'
            
            if not os.path.exists(file_path):
                return Response({'error': 'Файл не найден'}, status=status.HTTP_404_NOT_FOUND)
            
            if file_extension in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff']:
                with open(file_path, 'rb') as f:
                    response = HttpResponse(f.read(), content_type=content_type)
                    response['Content-Disposition'] = f'inline; filename="{filename}"'
                    response['Content-Length'] = file_obj.file_size
                    response['Accept-Ranges'] = 'bytes'
                    return response
            
            elif file_extension in ['.pdf']:
                with open(file_path, 'rb') as f:
                    response = HttpResponse(f.read(), content_type='application/pdf')

                    response['Content-Disposition'] = f'inline; filename="{filename}"'
                    return response
            
            else:
                def file_iterator():
                    with open(file_path, 'rb') as fh:
                        while True:
                            chunk = fh.read(8192)
                            if not chunk:
                                break
                            yield chunk
                
                response = StreamingHttpResponse(
                    file_iterator(),
                    content_type=content_type
                )
                response['Content-Disposition'] = f'attachment; filename="{filename}"'
                response['Content-Length'] = file_obj.file_size
                return response
            
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)