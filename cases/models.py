from django.db import models
from django.contrib.auth.models import User

class Organization(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField()

    def __str__(self):
        return self.name

class Project(models.Model):
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='projects')
    name = models.CharField(max_length=255)
    project_key = models.CharField(max_length=50, unique=True)

    def __str__(self):
        return f"{self.name} ({self.project_key})"

class Department(models.Model):
    DEPARTMENT_CHOICES = [
        ('MANAGEMENT', 'Management'),
        ('SALES', 'Sales'),
        ('ANALYST', 'Analyst'),
        ('DEVELOPER', 'Developer'),
    ]
    
    name = models.CharField(max_length=50, choices=DEPARTMENT_CHOICES, unique=True)

    def __str__(self):
        return self.name

class Role(models.Model):
    department = models.ForeignKey(Department, on_delete=models.CASCADE, related_name='roles')
    name = models.CharField(max_length=100)

    def __str__(self):
        return f"{self.name} in {self.department.name}"

class UserProfile(models.Model):
    STATUS_CHOICES = [
        ('ACTIVE', 'Active'),
        ('INACTIVE', 'Inactive'),
    ]

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='users')
    department = models.ForeignKey(Department, on_delete=models.CASCADE, related_name='users')
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name='users')
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    phone_number = models.CharField(max_length=15)
    date_of_birth = models.DateField()
    date_of_joining = models.DateField()
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='ACTIVE')

    def __str__(self):
        return f"{self.user.username} ({self.role.name})"

class Client(models.Model):
    TIMEZONE_CHOICES = [
        ('UTC', 'UTC'),
        ('PST', 'Pacific Standard Time'),
        ('EST', 'Eastern Standard Time'),
        ('CST', 'Central Standard Time'),
        ('GMT', 'Greenwich Mean Time'),
    ]

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='clients')
    name = models.CharField(max_length=255)
    phone_number = models.CharField(max_length=15)
    email = models.EmailField()
    timezone = models.CharField(max_length=50, choices=TIMEZONE_CHOICES)
    website = models.URLField(blank=True, null=True)
    signed_date = models.DateField()
    tenure = models.IntegerField()  # Number of years the client signed for
    amount_paid = models.DecimalField(max_digits=10, decimal_places=2)
    point_of_contact_name = models.CharField(max_length=255)
    point_of_contact_number = models.CharField(max_length=15)

    def __str__(self):
        return self.name

class SLA(models.Model):
    PRIORITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]

    priority = models.CharField(
        max_length=10, choices=PRIORITY_CHOICES, default='medium')
    time_limit_in_hours = models.IntegerField(help_text="Time limit in hours based on priority")

    def __str__(self):
        return f"SLA - {self.get_priority_display()} - {self.time_limit_in_hours} hrs"

    class Meta:
        verbose_name = "Service Level Agreement"
        verbose_name_plural = "Service Level Agreements"



class Ticket(models.Model):
    STATUS_CHOICES = [
        ('NEW', 'New'),
        ('IN_PROGRESS', 'In Progress'),
        ('RESOLVED', 'Resolved'),
        ('CLOSED', 'Closed'),
    ]
    
    PRIORITY_CHOICES = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]
    
    ticket_id = models.CharField(max_length=50, unique=True, editable=False)
    title = models.CharField(max_length=255)
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='NEW')
    priority = models.CharField(max_length=20, choices=PRIORITY_CHOICES, default='LOW')
    assignee = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='tickets')
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='tickets')
    organization = models.ForeignKey("Organization", on_delete=models.CASCADE, related_name='tickets')

    def save(self, *args, **kwargs):
        if not self.ticket_id:  # Only generate ticket_id if it's a new ticket
            last_ticket = Ticket.objects.filter(project=self.project).order_by('-created_at').first()
            if last_ticket:
                last_number = int(last_ticket.ticket_id.split('-')[-1])  # Extract number from last ticket_id
                new_number = last_number + 1
            else:
                new_number = 1
            self.ticket_id = f"{self.project.project_key}-{new_number}"
        
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.ticket_id}: {self.title} ({self.get_status_display()})"

    class Meta:
        ordering = ['-created_at']

class TicketComment(models.Model):
    ticket = models.ForeignKey(Ticket, on_delete=models.CASCADE, related_name='comments')
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    content = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Comment by {self.user.username} on {self.ticket.title}"

# class Comment(models.Model):
#     ticket = models.ForeignKey(Ticket, on_delete=models.CASCADE, related_name='comments')
#     user = models.ForeignKey(User, on_delete=models.CASCADE)
#     comment_text = models.TextField()
#     created_at = models.DateTimeField(auto_now_add=True)

#     def __str__(self):
#         return f"Comment by {self.user.username} on {self.ticket.title}"