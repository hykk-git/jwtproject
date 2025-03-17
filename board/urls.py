from django.urls import path
from .views import *

urlpatterns = [
    path('', MainView.as_view(), name='main'),
    path('signup/', SignupView.as_view(), name='signup'), 
    path('login/', LoginView.as_view(), name='login'),  
    path('logout/', LogoutView.as_view(), name='logout'),  
    path('board/', BoardView.as_view(), name='board'),
]