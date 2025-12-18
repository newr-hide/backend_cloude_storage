from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework import permissions
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError

from cloude_app.jwt_cookie_auth import BaseJWTAuthentication

class IsAdminUser(BaseJWTAuthentication):
    def has_permission(self, request, view):
        user = self.authenticate_user(request)
        return user and user.is_authenticated and user.is_admin

class IsAdminUserOrOwner(BaseJWTAuthentication):
    def has_object_permission(self, request, view, obj):
        user = self.authenticate_user(request)
        if not user:
            return False
        return user.is_admin or obj.user == user

          