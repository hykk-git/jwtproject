from django.contrib.auth.models import User
from rest_framework.response import Response
from django.contrib.auth import authenticate
from django.shortcuts import render, redirect
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.views import TokenRefreshView
from .serializers import *
from .models import *

### 메인 페이지 (루트)
class MainView(APIView):
    permission_classes = [AllowAny] 

    def get(self, request):
        return render(request, 'main.html')

###회원가입 (POST: username, password)
class SignupView(APIView):
    permission_classes = [AllowAny] 

    def get(self, request):
        if request.user.is_authenticated:
            return redirect('/')
        return render(request, 'signup.html')

    def post(self, request):
        serializer = SignupSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return redirect('/')  
        else:
            return render(request, 'signup.html', {"errors": serializer.errors})

### 로그인 (JWT 토큰 발급, 헤더에 포함)
class LoginView(APIView):
    permission_classes = [AllowAny] 

    def get(self, request):
        return render(request, 'login.html')

### 로그아웃 (JWT 방식에서는 클라이언트에서 토큰 삭제)
class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        return Response({"message": "로그아웃 성공 (토큰 삭제는 클라이언트에서 처리)"}, status=200)

### 게시판 조회 (JWT 인증 필수, 헤더에서 토큰 확인)
class BoardView(APIView):
    authentication_classes = [JWTAuthentication]  # JWT 인증 적용
    permission_classes = [IsAuthenticated]  # 인증된 사용자만 접근 가능

    def get(self, request):
        auth_header = request.headers.get("Authorization")  # 헤더에서 JWT 가져오기
        print("인증된 사용자:", request.user) 

        # 정상적으로 인증된 경우 게시판 데이터 반환
        posts = Post.objects.all()
        serializer = PostSerializer(posts, many=True)    

        return Response(serializer.data, status=200)
