from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import UserProfile,Organization, Project, Department, Role, User, Client, SLA,Ticket, TicketComment


# Register Organization model
class OrganizationAdmin(admin.ModelAdmin):
    list_display = ('name', 'description')
    search_fields = ('name',)
    list_per_page = 25

admin.site.register(Organization, OrganizationAdmin)


# Register Project model
class ProjectAdmin(admin.ModelAdmin):
    list_display = ('organization', 'name', 'project_key')
    list_filter = ('organization',)
    search_fields = ('name', 'project_key')
    list_per_page = 25

admin.site.register(Project, ProjectAdmin)


# # Register Department model
class DepartmentAdmin(admin.ModelAdmin):
    list_display = ('name',)
    search_fields = ('name',)
    list_per_page = 25

admin.site.register(Department, DepartmentAdmin)


# Register Role model
class RoleAdmin(admin.ModelAdmin):
    list_display = ('department', 'name')
    list_filter = ('department',)
    search_fields = ('name',)
    list_per_page = 25

admin.site.register(Role, RoleAdmin)

from django.contrib.auth.admin import UserAdmin
# Define UserProfile inline admin
class UserProfileInline(admin.StackedInline):
    model = UserProfile
    can_delete = False
    verbose_name_plural = 'Profile'
    fk_name = 'user'  # This is necessary because UserProfile has a OneToOneField to User

# Create a custom UserAdmin to include UserProfile
class CustomUserAdmin(UserAdmin):
    inlines = [UserProfileInline]  # Add the UserProfileInline here

    # Optionally, you can customize the fieldsets, list_display, etc.
    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        ('Personal info', {'fields': ('first_name', 'last_name', 'email')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
    )
    # List of fields to include in the admin form for the User model
    add_fieldsets = (
        (None, {'fields': ('username', 'password1', 'password2')}),
        ('Personal info', {'fields': ('first_name', 'last_name', 'email')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
    )

# Unregister the default UserAdmin and register the custom one
admin.site.unregister(User)
admin.site.register(User, CustomUserAdmin)



# Register Client model
class ClientAdmin(admin.ModelAdmin):
    list_display = ('organization', 'name', 'email', 'timezone', 'signed_date', 'tenure')
    list_filter = ('organization', 'timezone')
    search_fields = ('name', 'email')
    list_per_page = 25

admin.site.register(Client, ClientAdmin)


# Register SLA model
class SLAAdmin(admin.ModelAdmin):
    list_display = ('priority', 'time_limit_in_hours')  # Fields to display in list view
    list_filter = ('priority',)  # Filter by priority
    search_fields = ('priority',)  # Enable search by priority
    fieldsets = (
        (None, {
            'fields': ('priority', 'time_limit_in_hours')
        }),
    )
    ordering = ['priority']  # Order by priority
    list_per_page = 25  # Show 25 SLAs per page

admin.site.register(SLA, SLAAdmin)


class TicketCommentInline(admin.StackedInline):
    model = TicketComment

class TicketAdmin(admin.ModelAdmin):
    list_display = ['title', 'status', 'priority', 'assignee', 'organization', 'created_at']
    list_filter = ['status', 'priority', 'organization']
    search_fields = ['title', 'description']
    inlines = [TicketCommentInline]

admin.site.register(Ticket, TicketAdmin)
admin.site.register(TicketComment)
