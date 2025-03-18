from django.contrib.auth.models import User
from rest_framework.response import Response
from django.contrib.auth import authenticate
from django.shortcuts import render, redirect
from rest_framework import status
from rest_framework.views import APIView
from django.contrib.auth.hashers import check_password
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.authentication import JWTAuthentication
from .serializers import *
from .models import *

class MainView(APIView):
    permission_classes = [AllowAny] 

    def get(self, request):
        return render(request, 'main.html')

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

class LoginView(APIView):
    permission_classes = [AllowAny] 

    def get(self, request):
        return render(request, 'login.html')

    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")

        user = authenticate(username=username, password=password) 

        if user is None:
            return Response(
                {"message": "존재하지 않는 아이디이거나 비밀번호가 틀렸습니다."},
                status=status.HTTP_400_BAD_REQUEST
            )

        token = TokenObtainPairSerializer.get_token(user)
        access_token = str(token.access_token)
        refresh_token = str(token)

        return Response({
            "message": "로그인 성공",
            "access_token": access_token,
            "refresh_token": refresh_token,
        }, status=status.HTTP_200_OK)
    
class LogoutView(APIView):
    permission_classes = [IsAuthenticated]  

    def post(self, request):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            
            # access token 무효화
            token.blacklist()  
            return Response({"message": "로그아웃 성공"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": "잘못된 요청"}, status=status.HTTP_400_BAD_REQUEST)

class BoardView(APIView):
    authentication_classes = [JWTAuthentication]  # JWT 인증 적용 (자동 인증)
    permission_classes = [IsAuthenticated]  # 로그인한 사용자만 접근 가능

    def get(self, request):
        # JWTAuthentication이 자동으로 `request.user`를 설정해줌
        posts = Post.objects.all()
        serializer = PostSerializer(posts, many=True)
        return render(request, 'board.html', {'posts': serializer.data})