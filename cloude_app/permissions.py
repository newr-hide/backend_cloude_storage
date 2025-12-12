
from rest_framework import permissions

class IsAdminUser(permissions.BasePermission):

        # Доступ только админам

    class IsAdminUser(permissions.BasePermission):
        def has_permission(self, request, view):
            return request.user.is_authenticated and request.user.is_admin
        
class IsAdminUserOrOwner(permissions.BasePermission):

   # Разрешение для администраторов или владельца объекта

    def has_object_permission(self, request, view, obj):

        if request.user.is_admin:
            return True
        return obj.user == request.user