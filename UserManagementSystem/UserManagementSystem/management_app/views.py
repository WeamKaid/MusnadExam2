from django.contrib.auth.hashers import make_password
from django.contrib.auth import authenticate, login
from django.shortcuts import redirect, render
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from .models import ActivityLog, User, Role, Permission
from .models import UserRole, RolePermission as RPModel
from .serializers import SensitiveDataSerializer, UserSerializer, RoleSerializer, PermissionSerializer
import jwt
from datetime import datetime, timedelta, timezone
from django.conf import settings
from rest_framework.permissions import IsAuthenticated, BasePermission
import hashlib

class RegisterView(APIView):
    def post(self, request):
        username = request.data.get('username')
        email = request.data.get('email')
        password = request.data.get('password')

        # Validate input data
        if not username or not email or not password:
            return Response({'error': 'Missing required fields'}, status=status.HTTP_400_BAD_REQUEST)

        # Check for uniqueness of username and email
        if User.objects.filter(username=username).exists():
            return Response({'error': 'Username already exists'}, status=status.HTTP_400_BAD_REQUEST)
        if User.objects.filter(email=email).exists():
            return Response({'error': 'Email already exists'}, status=status.HTTP_400_BAD_REQUEST)

        # Hash the password
        hashed_password = make_password(password)

        # Create the user
        user = User.objects.create(
            username=username,
            email=email,
            password=hashed_password
        )
        user.save()

        return Response({'message': 'User registered successfully'}, status=status.HTTP_201_CREATED)
    

class LoginView(APIView):
    def post(self, request):
        username_or_email = request.data.get('username_or_email')
        password = request.data.get('password')

        # Retrieve the user information from the database
        try:
            user = User.objects.get(username=username_or_email)
        except User.DoesNotExist:
            try:
                user = User.objects.get(email=username_or_email)
            except User.DoesNotExist:
                return Response({'error': 'Invalid username/email or password'}, status=status.HTTP_401_UNAUTHORIZED)

        # Verify the password
        if not user.check_password(password):
            return Response({'error': 'Invalid username/email or password'}, status=status.HTTP_401_UNAUTHORIZED)

        # Generate and return a JWT token
        payload = {
            'user_id': user.id,
            'exp': datetime.utcnow() + timedelta(hours=24)
        }
        token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')

        return Response({'token': token}, status=status.HTTP_200_OK)
    

class RoleViewSet(APIView):
    def get(self, request):
        roles = Role.objects.all()
        serializer = RoleSerializer(roles, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = RoleSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, pk):
        role = Role.objects.get(pk=pk)
        serializer = RoleSerializer(role, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        role = Role.objects.get(pk=pk)
        role.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

class PermissionViewSet(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        permissions = Permission.objects.all()
        serializer = PermissionSerializer(permissions, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        serializer = PermissionSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, pk):
        permission = Permission.objects.get(pk=pk)
        serializer = PermissionSerializer(permission, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        permission = Permission.objects.get(pk=pk)
        permission.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
    
class RolePermission(BasePermission):
    def has_permission(self, request, view):
        # Get the user's assigned roles
        user_roles = UserRole.objects.filter(user=request.user)

        # Check if the user has the required permissions based on their roles
        required_permissions = view.required_permissions
        for role in user_roles:
            role_permissions = RPModel.objects.filter(role=role.role)
            if all(rp.permission.name in required_permissions for rp in role_permissions):
                return True

        return False

class SensitiveView(APIView):
    permission_classes = [RolePermission]
    required_permissions = ['view_sensitive_data', 'edit_sensitive_data']

def get(self, request):
    """
    Retrieve sensitive data.
    """
    try:
        sensitive_data = sensitive_data.objects.all()
        serializer = SensitiveDataSerializer(sensitive_data, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

def post(self, request):
    """
    Update sensitive data.
    """
    try:
        serializer = SensitiveDataSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(status=status.HTTP_204_NO_CONTENT)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    

def reset_password(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        reset_token = request.POST.get('reset_token')
        new_password = request.POST.get('new_password')

        user = User.objects.filter(email=email, password_reset_token=reset_token, password_reset_expiration__gte=timezone.now()).first()
        if user:
            user.password = make_password(new_password)
            user.password_reset_token = None
            user.password_reset_expiration = None
            user.save()
            success_message = 'Password reset successful.'
            return render(request, 'reset_password.html', {'success_message': success_message})
        else:
            error_message = 'Invalid email or reset token.'
            return render(request, 'reset_password.html', {'error_message': error_message})
    else:
        return render(request, 'reset_password.html')
    
    
def log_user_activity(user, action, details=None):
    hash_str = f"{user.id}:{action}:{details}:{timezone.now()}"
    hash_value = hashlib.sha256(hash_str.encode()).hexdigest()
    ActivityLog.objects.create(user=user, action=action, details=details, hash=hash_value)

def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)
        if user is not None:
            log_user_activity(user, 'Login')
            login(request, user)
            return redirect('dashboard')  # Assuming you have a 'dashboard' URL name
        else:
            error_message = 'Invalid username or password.'
            return render(request, 'login.html', {'error_message': error_message})
    else:
        return render(request, 'login.html')