from django.urls import path
from .views import *

urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
    path('absadmin/', AdminDashboardView.as_view(), name='admin_dashboard'),
    path('absuser/', UserDashboardView.as_view(), name='user_dashboard'),
    path('updatepwd/', UpdatePasswordView.as_view(), name='update_password'),
    path('registeruser/', RegisterUserView.as_view(), name='register_user'),
    path('updateuser/', UpdateUserView.as_view(), name='update_user'),
    path('dailyreport/', DailyReportView.as_view(), name='daily_report'),
    path('dailyreport/<int:report_id>/', DailyReportView.as_view(), name='daily_report_detail'),
    # path('acceptreport/', AcceptReportView.as_view(), name='accept_report'),
    # path('denyreport/', DenyReportView.as_view(), name='deny_report'),
    path('report/action/', ReportActionView.as_view(), name='report_action'),
    path('approvalhistory/', ApprovalHistoryView.as_view(), name='approval_history'),
]
