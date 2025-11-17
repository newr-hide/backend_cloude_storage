
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import UserViewSet, UserFileViewSet

router = DefaultRouter()
router.register(r'users', UserViewSet)
router.register(r'files', UserFileViewSet)


urlpatterns = [
    path('api/', include(router.urls)),
]


