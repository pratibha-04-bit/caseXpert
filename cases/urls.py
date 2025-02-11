from django.urls import path
from . import views

urlpatterns = [

    path('',views.base,name='base'),
    path('alert',views.alert,name='alert'),
    # Organization CRUD
    path('create_organization/', views.create_organization, name='create_organization'),
    path('organization_list/', views.organization_list, name='organization_list'),
    path('edit_organization/<int:org_id>/', views.edit_organization, name='edit_organization'),
    path('delete_organization/<int:org_id>/', views.delete_organization, name='delete_organization'),

    # Project CRUD
    path('create_project/', views.create_project, name='create_project'),
    path('project_list/', views.project_list, name='project_list'),
    path('edit_project/<int:project_id>/', views.edit_project, name='edit_project'),
    path('delete_project/<int:project_id>/', views.delete_project, name='delete_project'),

    # Department CRUD
    path('create_department/', views.create_department, name='create_department'),
    path('department_list/', views.department_list, name='department_list'),
    path('edit_department/<int:department_id>/', views.edit_department, name='edit_department'),
    path('delete_department/<int:department_id>/', views.delete_department, name='delete_department'),

    # Role CRUD
    path('create_role/', views.create_role, name='create_role'),
    path('role_list/', views.role_list, name='role_list'),
    path('edit_role/<int:role_id>/', views.edit_role, name='edit_role'),
    path('delete_role/<int:role_id>/', views.delete_role, name='delete_role'),

    # User CRUD
    path('create_user/', views.create_user, name='create_user'),
    path('user_list/', views.user_list, name='user_list'),
    path('edit_user/<int:user_id>/', views.edit_user, name='edit_user'),
    path('delete_user/<int:user_id>/', views.delete_user, name='delete_user'),

    # Client CRUD
    path('create_client/', views.create_client, name='create_client'),
    path('client_list/', views.client_list, name='client_list'),
    path('edit_client/<int:client_id>/', views.edit_client, name='edit_client'),
    path('delete_client/<int:client_id>/', views.delete_client, name='delete_client'),

    # SLA CRUD operations
    path('create_sla/', views.create_sla, name='create_sla'),
    path('sla_list/', views.sla_list, name='sla_list'),
    path('edit_sla/<int:sla_id>/', views.edit_sla, name='edit_sla'),
    path('delete_sla/<int:sla_id>/', views.delete_sla, name='delete_sla'),

    # ticket
    path('tickets/', views.ticket_list, name='ticket_list'),
    path('ticket/create/', views.create_ticket, name='create_ticket'),
    # path('ticket/<int:ticket_id>/update/', views.update_ticket, name='update_ticket'),
    path('ticket/<int:ticket_id>/update/', views.ticket_description, name='update_ticket'),
    path('ticket_data/', views.list_ticket, name='ticket_data'),
    # path('handle_alert_submission/', views.handle_alert_submission, name='handle_alert_submission'),
    path('attack_matrix/', views.attack_matrix, name='attack_matrix'),

    ]