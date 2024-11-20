from rest_framework import serializers
from .models import User, Tag, Task, Subtask, Comment, DueDateExtensionRequest, Notifications

class UserRegistrationSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=50)
    email = serializers.EmailField(max_length=50)
    role = serializers.CharField(max_length=10)
    password = serializers.CharField(max_length=150, allow_null=False, write_only=True)


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()



class TagSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tag
        fields = ['id', 'name']

class TaskSerializer(serializers.ModelSerializer): 
    tags = TagSerializer(many=True, read_only=True)
    class Meta:
        model = Task
        fields = ['id','title', 'description', 'due_date', 'is_completed', 'priority', 'category', 'status', 'tags', 'assigned_to', 'created_at', 'updated_at']
        read_only_fields = ['created_at', 'updated_at'] 


class CommentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Comment
        fields = ['id', 'task', 'user', 'content', 'created_at']
        read_only_fields = ['id', 'created_at']


class SubtaskSerializer(serializers.ModelSerializer):
    class Meta:
        model=Subtask
        fields = ['id', 'parent_task', 'title', 'is_completed', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']

class DueDateExtensionRequestSerializer(serializers.ModelSerializer):
    class Meta:
        model=DueDateExtensionRequest
        fields = ['id', 'task', 'user', 'requested_date', 'is_approved', 'created_at']
        read_only_fields=['id', 'created_at']


class NotificationsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notifications
        fields = ['id', 'user', 'message', 'created_at']
        read_only_fields = ['id', 'created_at']