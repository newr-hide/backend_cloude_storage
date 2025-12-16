
from django.contrib import admin
from django.urls import path, include
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
)
from cloude_app.views import CustomTokenRefreshView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('cloude_app.urls')),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', CustomTokenRefreshView.as_view(), name='token_refresh'),
    
]
