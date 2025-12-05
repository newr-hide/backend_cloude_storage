
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import CreateShareLinkView, DeleteFileView, MyTokenObtainPairView, PublicDownloadView, RegisterViewSet, UserFileViewSet, UserDetailView, DownloadFileView


router = DefaultRouter()
router.register(r'users', RegisterViewSet, basename='users')
router.register(r'files', UserFileViewSet, basename='files')



urlpatterns = [
    path('api/', include(router.urls)),
    path('api/auth', MyTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/users/<int:id>/', UserDetailView.as_view(), name='user-detail'),
    path('api/download/<int:pk>/', DownloadFileView.as_view(), name='download'),
    path('api/files/<int:pk>/delete/', DeleteFileView.as_view(), name='delete-file'),
    path('api/create-share-link/', CreateShareLinkView.as_view(), name='create-share-link'),
    path('api/download-public/<str:token>/', PublicDownloadView.as_view(), name='public-download'),

]


