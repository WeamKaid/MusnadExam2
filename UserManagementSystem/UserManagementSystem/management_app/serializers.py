from rest_framework import serializers
from .models import User, Role, Permission, UserRole, RolePermission
from .models import SensitiveData

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'password']
        extra_kwargs = {'password': {'write_only': True}}

class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = ['id', 'name', 'description']

class RoleSerializer(serializers.ModelSerializer):
    permissions = PermissionSerializer(many=True, read_only=True)

    class Meta:
        model = Role
        fields = ['id', 'name', 'description', 'permissions']

class UserRoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserRole
        fields = ['id', 'user', 'role']

class RolePermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = RolePermission
        fields = ['id', 'role', 'permission']


class SensitiveDataSerializer(serializers.ModelSerializer):
    """
    Serializer for the SensitiveData model.
    """
    class Meta:
        model = SensitiveData
        fields = '__all__'
        read_only_fields = ('id',)

    def validate(self, data):
        """
        Validate the sensitive data.
        """
        # Add your custom validation logic here
        # For example, you can check if the data is within acceptable limits
        if 'sensitive_field' in data and len(data['sensitive_field']) > 100:
            raise serializers.ValidationError("Sensitive field must be less than 100 characters.")
        return data