from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework import permissions
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError

class BaseJWTAuthentication(permissions.BasePermission):
    def get_token_from_request(self, request):
        auth_header = request.headers.get('Authorization')
        jwt_cookie = request.COOKIES.get('access_token')
        
        if auth_header:
            return auth_header.split()[1]
        if jwt_cookie:
            return jwt_cookie
        return None

    def authenticate_user(self, request):
        auth = JWTAuthentication()
        token = self.get_token_from_request(request)
        
        if not token:
            return None
        
        try:
            validated_token = auth.get_validated_token(token)
            user = auth.get_user(validated_token)
            return user
        except (InvalidToken, TokenError):
            return None