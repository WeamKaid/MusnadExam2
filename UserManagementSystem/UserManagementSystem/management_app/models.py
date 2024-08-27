from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.db import models
from django.utils.crypto import get_random_string
from django.core.mail import send_mail
from django.utils import timezone
from datetime import timedelta

class UserManager(BaseUserManager):
    def create_user(self, username, email, password=None):
        if not email:
            raise ValueError('You must have an email address')

        user = self.model(
            username=username,
            email=self.normalize_email(email),
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password=None):
        user = self.create_user(
            username=username,
            email=email,
            password=password,
        )
        user.is_admin = True
        user.save(using=self._db)
        return user

class User(AbstractBaseUser):
    username = models.CharField(max_length=50, unique=True)
    email = models.EmailField(verbose_name='email address', max_length=255, unique=True)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)

    objects = UserManager()

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        return True

    def has_module_perms(self, app_label):
        return True

    @property
    def is_staff(self):
        return self.is_admin

class Permission(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField()

class Role(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField()
    permissions = models.ManyToManyField(Permission, through='RolePermission')

class UserRole(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)

class RolePermission(models.Model):
    role = models.ForeignKey(Role, on_delete=models.CASCADE)
    permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

def assign_role_to_user(user_id, role_id):
    user = User.objects.get(pk=user_id)
    role = Role.objects.get(pk=role_id)
    UserRole.objects.create(user=user, role=role)

def define_permissions_for_role(role_id, permission_ids):
    role = Role.objects.get(pk=role_id)
    permissions = Permission.objects.filter(pk__in=permission_ids)
    for permission in permissions:
        RolePermission.objects.create(role=role, permission=permission)

def forgot_password(email):
    user = User.objects.filter(email=email).first()
    if user:
        reset_token = get_random_string(length=32)
        user.password_reset_token = reset_token
        user.password_reset_expiration = timezone.now() + timedelta(hours=24)
        user.save()
        send_password_reset_email(user.email, reset_token)
        return {'message': 'Password reset instructions sent to your email.'}
    return {'message': 'No user found with the provided email.'}

def send_password_reset_email(email, reset_token):
    subject = 'Password Reset Request'
    message = f'Please use the following token to reset your password: {reset_token}'
    send_mail(subject, message, 'from@example.com', [email], fail_silently=False)

class ActivityLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    action = models.CharField(max_length=100)
    timestamp = models.DateTimeField(auto_now_add=True)
    details = models.TextField(null=True, blank=True)
    hash = models.CharField(max_length=255)

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    phone_number = models.CharField(max_length=20)
    address = models.CharField(max_length=200)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    status = models.CharField(max_length=20, default='active')

    def __str__(self):
        return f"{self.user.username}'s Profile"

class UserActivity(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    activity_type = models.CharField(max_length=50)
    timestamp = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, default='active')

    def __str__(self):
        return f"{self.user.username} - {self.activity_type} - {self.timestamp}"