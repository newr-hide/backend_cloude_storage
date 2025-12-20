import mimetypes
from django.http import HttpResponse, StreamingHttpResponse

from cloude_app.file_services import FileService
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
    serializer_class = UserFileSerializer
    parser_classes = [MultiPartParser, FormParser, JSONParser]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter]
    filterset_fields = ['user', 'uploaded_at']
    search_fields = ['original_name', 'comment']

    def get_permissions(self):
        if self.action in ['list', 'retrieve', 'destroy']:
            return [IsAdminUser()]
        elif self.action in ['update', 'partial_update']:
            return [IsAdminUserOrOwner()]
        return [permissions.IsAuthenticated()]

    def get_queryset(self):
        file_service = FileService(user=self.request.user, request=self.request)
        return file_service.get_queryset()

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        file_service = FileService(user=self.request.user, request=self.request)
        file_service.create_file(serializer.validated_data)
        
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def update(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            serializer = self.get_serializer(
                instance, 
                data=request.data, 
                partial=True
            )
            serializer.is_valid(raise_exception=True)
            
            file_service = FileService(request.user)
            updated_instance = file_service.update_file(
                instance, 
                serializer.validated_data
            )
            
            return Response(
                self.get_serializer(updated_instance).data
            )
        
        except PermissionError:
            return Response(status=status.HTTP_403_FORBIDDEN)
        
        except APIException as e:
            return Response(
                {'error': str(e)}, 
                status=status.HTTP_400_BAD_REQUEST
            )
            
        except Exception as e:
            return Response(
                {'error': f'Произошла ошибка: {str(e)}'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
    def retrieve(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            file_service = FileService(request.user)
            updated_instance = file_service.update_last_downloaded(instance)
            serializer = self.get_serializer(updated_instance)
            return Response(serializer.data)
        except Exception as e:
            return Response(
                {'error': str(e)}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        file_service = FileService(user=self.request.user, request=self.request)
        file_service.delete_file(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)
    
    
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
            file_service = FileService(user=request.user)
            file_obj = file_service.get_file_by_id(pk)
            updated_file = file_service.update_last_downloaded(file_obj)
            file_path, filename = file_service.download_file(file_obj)
            
            content_type = mimetypes.guess_type(file_path)[0] or 'application/octet-stream'
            
            with open(file_path, 'rb') as fh:
                response = HttpResponse(fh.read(), content_type=content_type)
                response['Content-Disposition'] = f'attachment; filename="{filename}"'
                return response
            
        except FileNotFoundError as e:
            return Response({'error': str(e)}, status=404)
        except Exception as e:
            return Response({'error': str(e)}, status=500)
    
class DeleteFileView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def delete(self, request, pk):
        try:
            file_service = FileService(user=request.user)
            file_obj = file_service.get_file_by_id(pk)
            file_service.delete_file(file_obj)
            return Response({'message': 'Файл удален'}, status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

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
            file_service = FileService(user=request.user)
            file_obj = file_service.get_file_by_id(file_id)
            link = file_service.create_share_link(file_obj)
            
            base_url = request.build_absolute_uri('/api/download-public/')
            share_url = f"{base_url}{link.token}"
            
            return Response({'share_url': share_url}, status=status.HTTP_201_CREATED)
        
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

    def destroy(self, request, id):
        # print('Запуск')
        try:
            user = self.get_object() 
            user.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            print(f"Ошибка при удалении: {str(e)}") 
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def partial_update(self, request, id):
        print('Запуск partial_update') 
        try:
            print('Запуск partial_update')  
            user = self.get_object()
            print(f"Получен пользователь: {user.login}")
            
            is_admin = request.data.get('is_admin', None)
            
            if is_admin is not None:
                user.is_admin = is_admin
                user.save()
                return Response(self.serializer_class(user).data, status=status.HTTP_200_OK)
            
            return Response({'error': 'Параметр is_admin не передан'}, status=status.HTTP_400_BAD_REQUEST)
        
        except Exception as e:
            print(f"Ошибка при обновлении: {str(e)}")
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


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