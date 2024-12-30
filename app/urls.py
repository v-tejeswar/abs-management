from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from .views import *

urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),  # Obtain JWT tokens
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),  # Refresh JWT token
    path('absadmin/', AdminDashboardView.as_view(), name='admin_dashboard'),
    path('absuser/', UserDashboardView.as_view(), name='user_dashboard'),
    path('updatepwd/', UpdatePasswordView.as_view(), name='update_password'),
    path('registeruser/', RegisterUserView.as_view(), name='register_user'),
    path('updateuser/', UpdateUserView.as_view(), name='update_user'),
    path('dailyreport/', DailyReportView.as_view(), name='daily_report'),
    path('updatereport/<int:report_id>/', UpdateReportView.as_view(), name='update_report'),
    path('userreports/', ApprovedReportsByUserView.as_view(), name='user_reports'),
    path('getreports/', GetReportsView.as_view(), name='get_report'),
    path('action/', ReportActionView.as_view(), name='report_action'),
    path('approvalhistory/', ApprovalHistoryView.as_view(), name='approval_history'),
]
