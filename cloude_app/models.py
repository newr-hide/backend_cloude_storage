
import os
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin, Group, Permission
from django.forms import ValidationError
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
import uuid

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
        user.is_active = True
        user.is_superuser = True  
        user.save(using=self._db)
        return user
    
class User(AbstractBaseUser, PermissionsMixin):
    login = models.CharField(max_length=30, unique=True)
    email = models.EmailField(unique=True)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)
    objects = UserManager()
    groups = models.ManyToManyField(
        Group,
        related_name='custom_user_groups',  
        verbose_name=_('groups'),
        blank=True,
        help_text=_('The groups this user belongs to.'),
        related_query_name='custom_user'
    )
    
    user_permissions = models.ManyToManyField(
        Permission,
        related_name='custom_user_permissions',  
        verbose_name=_('user permissions'),
        blank=True,
        help_text=_('User specific permissions.'),
        related_query_name='custom_user'
    )
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

    original_name = models.CharField(max_length=255, blank=True, null=True)
    last_downloaded = models.DateTimeField(blank=True, null=True)
    file_size = models.PositiveIntegerField(blank=True, null=True)

    def save(self, *args, **kwargs):

        if not self.original_name:
            self.original_name = os.path.basename(self.file.name)
        
        if not self.file_size:
            self.file_size = self.file.size
        
        super().save(*args, **kwargs)

    def download(self):
        self.last_downloaded = timezone.now()
        self.save()

    def delete(self, *args, **kwargs):
        try:
            if self.file:
                if os.path.isfile(self.file.path):
                    os.remove(self.file.path)
        except Exception as e:
            print(f"Ошибка при удалении файла: {str(e)}")
        super().delete(*args, **kwargs)

    def __str__(self):
        return f'{self.user.login} - {self.file.name}'
    
class FileShareLink(models.Model):
    file = models.ForeignKey('UserFile', on_delete=models.CASCADE)
    token = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    def clean(self):
        if self.expires_at <= timezone.now():
            raise ValidationError('Дата истечения не может быть в прошлом')
    
    def save(self, *args, **kwargs):
        self.full_clean() 
        super().save(*args, **kwargs)

    def is_expired(self):
        return timezone.now() > self.expires_at