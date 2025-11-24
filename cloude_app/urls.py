
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import MyTokenObtainPairView, RegisterViewSet, UserFileViewSet, UserDetailView


router = DefaultRouter()
router.register(r'users', RegisterViewSet, basename='users')
router.register(r'files', UserFileViewSet, basename='files')



urlpatterns = [
    path('api/', include(router.urls)),
    path('api/auth', MyTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/users/<int:id>/', UserDetailView.as_view(), name='user-detail')
]


