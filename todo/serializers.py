from django.contrib.auth.models import Group, User
from rest_framework import serializers
from .models import Todo
from rest_framework import serializers

class UserSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'date_joined']

class TodoSerializer(serializers.HyperlinkedModelSerializer):
    
    user = serializers.PrimaryKeyRelatedField(read_only=True, default=serializers.CurrentUserDefault())
    class Meta:
        model = Todo
        fields = ['id','title', 'description', 'created_at', 'user', 'time_passed']

