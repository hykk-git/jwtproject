from django.contrib.auth.models import User
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from .models import Post

class SignupSerializer(serializers.ModelSerializer):
    # 입력한 회원가입 정보 저장, JSON 반환
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['username', 'password']

    def create(self, validated_data):
        user = User(
            username=validated_data['username'],
        )
        user.set_password(validated_data['password'])  
        user.save()
        return user

class PostSerializer(serializers.ModelSerializer):
    # 글 객체를 JSON으로 반환
    class Meta:
        model = Post
        fields = ['id', 'title', 'content', 'author', 'created_at']