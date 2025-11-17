from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

class UserManager(BaseUserManager):
    def create_user(self, login, email, password=None):
        if not email:
            raise ValueError('Email is required')
        if not login:
            raise ValueError('Login is required')
            
        user = self.model(
            login=login,
            email=self.normalize_email(email),
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, login, email, password=None):
        user = self.create_user(
            login=login,
            email=email,
            password=password,
        )
        user.is_admin = True
        user.save(using=self._db)
        return user
    
class User(AbstractBaseUser, PermissionsMixin):
    login = models.CharField(max_length=30, unique=True)
    email = models.EmailField(unique=True)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)
    
    objects = UserManager()
    
    USERNAME_FIELD = 'login'
    REQUIRED_FIELDS = ['email']
    
    def __str__(self):
        return self.login
        
    @property
    def is_staff(self):
        return self.is_admin
    
class UserFile(models.Model):
    user = models.ForeignKey(User, related_name='files', on_delete=models.CASCADE)
    file = models.FileField(upload_to='user_files/')
    comment = models.TextField(verbose_name="Комментарий", blank=True, default='')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f'{self.user.login} - {self.file.name}'