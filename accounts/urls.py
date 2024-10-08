from django.urls import path
from .import views


urlpatterns = [
    path('register/', views.register, name='register'),
    path('login/', views.login, name='login'),
    path('logout/', views.logout, name='logout'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('', views.dashboard, name='dashboard'),

    path('activate/<uidb64>/<token>/', views.activate, name='activate'),
    path('forgot_password/', views.forgot_password, name='forgot_password'),
    path('reset_password_vaildate/<uidb64>/<token>/', views.reset_password_vaildate, name='reset_password_vaildate'),
    path('resetPassword/', views.resetPassword, name='resetPassword'),

]