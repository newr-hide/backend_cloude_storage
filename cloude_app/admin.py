from django.contrib import admin


from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User

class UserAdmin(BaseUserAdmin):
    list_display = ('login', 'email', 'is_active', 'is_admin')
    search_fields = ('login', 'email')
    readonly_fields = ('date_joined',)
    filter_horizontal = ()
    list_filter = ('is_admin',)
    fieldsets = (
        (None, {'fields': ('login', 'email', 'password')}),
        ('Permissions', {'fields': ('is_active', 'is_admin')}),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('login', 'email', 'password1', 'password2')
        }),
    )
    ordering = ('login',)
admin.site.register(User, UserAdmin)
