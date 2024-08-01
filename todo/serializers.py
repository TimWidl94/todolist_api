from rest_framework import serializers
from todo.models import TodoItem
from django.contrib.auth.models import User
import logging

class TodoItemSerializer(serializers.ModelSerializer):
    class Meta:
        model = TodoItem
        fields = '__all__'
        read_only_fields = ['author']
        
    def create(self, validated_data):
        request = self.context.get('request')
        if request and hasattr(request, 'user'):
            if request.user.is_authenticated:
                validated_data['author'] = request.user
                logging.debug(f"User {request.user} authenticated and set as author.")
            else:
                logging.error("User is not authenticated.")
                raise serializers.ValidationError("User is not authenticated.")
        else:
            logging.error("Request context is missing or user is not in request.")
            raise serializers.ValidationError("Request context is missing or user is not in request.")
        
        return super().create(validated_data)
    
      
class RegistrationSerializer(serializers.ModelSerializer):
    password_confirm = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ('username', 'password', 'password_confirm', 'email')
        extra_kwargs = {'password': {'write_only': True}}

    def validate(self, data):
        if data['password'] != data['password_confirm']:
            raise serializers.ValidationError("Passwords do not match")
        return data

    def create(self, validated_data):
        validated_data.pop('password_confirm')
        user = User.objects.create_user(**validated_data)
        return user