from rest_framework.response import Response
from django.shortcuts import render, redirect
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
from .serializers import *
from .models import *

# 메인 페이지 (루트)
class MainView(APIView):
    permission_classes = [AllowAny] 

    def get(self, request):
        return render(request, 'main.html')

# 회원가입
class SignupView(APIView):
    permission_classes = [AllowAny] 

    def get(self, request):
        # 이미 로그인된 사용자는 main으로 이동
        if request.user.is_authenticated:
            return redirect('/')
        return render(request, 'signup.html')

    def post(self, request):
        # 유저가 입력한 회원가입 정보(id, pw)를 DB에 저장
        serializer = SignupSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return redirect('/')  
        else:
            return render(request, 'signup.html', {"errors": serializer.errors})

# 로그인
class LoginView(APIView):
    permission_classes = [AllowAny] 

    def get(self, request):
        return render(request, 'login.html')

# 로그아웃
class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    # 로그아웃시 토큰 삭제 필요(클라이언트에서 처리)
    def post(self, request):
        return Response({"message": "로그아웃 성공"}, status=200)

# 게시판 조회
class BoardView(APIView):
    # JWT 인증 적용, Authorization 헤더 확인
    authentication_classes = [JWTAuthentication]  
    # 인증된 사용자만 접근 가능한 View
    permission_classes = [IsAuthenticated]  

    def get(self, request):
        auth_header = request.headers.get("Authorization")
        print("인증된 사용자:", request.user) 

        # 정상적으로 인증된 경우 게시판 데이터 반환
        posts = Post.objects.all()
        serializer = PostSerializer(posts, many=True)    

        return Response(serializer.data, status=200)
