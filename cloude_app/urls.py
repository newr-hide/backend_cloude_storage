
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import AdminFileFilterView, AdminUserViewSet, CreateShareLinkView, DeleteFileView, LogoutView, MyTokenObtainPairView, PublicDownloadView, RegisterViewSet, ShowFileView, UserFileViewSet, UserDetailView, DownloadFileView


router = DefaultRouter()
router.register(r'users', RegisterViewSet, basename='users')
router.register(r'files', UserFileViewSet, basename='files')
router.register(r'admin/users', AdminUserViewSet, basename='admin-users')



urlpatterns = [
    path('api/', include(router.urls)),
    path('api/auth', MyTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/auth/logout/', LogoutView.as_view(), name='logout'),
    path('api/users/<int:id>/', UserDetailView.as_view(), name='user-detail'),
    path('api/download/<int:pk>/', DownloadFileView.as_view(), name='download'),
    path('api/files/<int:pk>/delete/', DeleteFileView.as_view(), name='delete-file'),
    path('api/create-share-link/', CreateShareLinkView.as_view(), name='create-share-link'),
    path('api/download-public/<str:token>/', PublicDownloadView.as_view(), name='public-download'),
    path('api/admin/users/<int:user_id>/files/', AdminFileFilterView.as_view(), name='user-files-filter'),
    path('api/show-file/<int:pk>/', ShowFileView.as_view(), name='show-file'),
]


