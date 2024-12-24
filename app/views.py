from django.contrib.auth.hashers import check_password
from django.db import IntegrityError
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import User, DailyReport, ApprovalHistory
from .serializers import DailyReportSerializer


# Helper function for role-based access control
def is_admin(user_role):
    return user_role == 'admin'

class LoginView(APIView):
    permission_classes = [AllowAny]  # Allow unauthenticated users to access this endpoint

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')  # User-input plain password

        try:
            if not email:
                return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)

            user = User.objects.get(email=email)  # Fetch user by email

            # Use check_password to compare user-input password with database password
            if check_password(password, user.password):
                request.session['user_id'] = user.id
                request.session['user_email'] = user.email
                request.session['user_role'] = user.role
                request.session['user_phone_number'] = user.phone_number
                return Response({'id':f'{user.id}','name': f'{user.first_name}',
                                 'phone_number':f'{user.phone_number if user.phone_number else "Not Provided"}',
                                 'role': f'{user.role}'},
                                status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
        except User.DoesNotExist:
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)


class AdminDashboardView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):

        if not is_admin(request.session.get('user_role')):
            raise PermissionDenied("Access denied")
        # Return admin dashboard details
        return Response({"message": "Admin dashboard details"})

class UserDashboardView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Return user dashboard details
        return Response({"message": "User dashboard details"})

class UpdatePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # Check if the user is authenticated
        user_id = request.session.get('user_id')

        if not user_id:
            raise PermissionDenied("Authentication credentials were not provided.")

        # Fetch the user instance
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            raise PermissionDenied("User not found.")

        # Proceed with password update
        new_password = request.data.get('new_password')
        user.set_password(new_password)
        user.save()

        return Response({"message": "Password updated successfully"})

class RegisterUserView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        if not is_admin(request.session.get('user_role')):
            raise PermissionDenied("Access denied")
        email = request.data.get('email')
        password = request.data.get('password')
        role = request.data.get('role', 'user')
        first_name = request.data.get('first_name')
        last_name = request.data.get('last_name')
        phone_number = request.data.get("phone_number")
        try:
            # Check if a user with the same email already exists
            if User.objects.filter(email=email).exists():
                return Response(
                    {"error": f"User with email {email} already exists"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            user = User.objects.create_user(username=email, email=email, password=password, role=role,
                                        first_name=first_name, last_name=last_name,phone_number=phone_number)
            return Response(
                {"message": f"User {email} with id - {user.id} registered successfully."},
                status=status.HTTP_201_CREATED,
            )

        except IntegrityError as e:
            return Response(
                {"error": "Database error occurred", "details": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class UpdateUserView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        if not is_admin(request.session.get('user_role')):
            raise PermissionDenied("Access denied")
        user_id = request.data.get('user_id')
        user = get_object_or_404(User, id=user_id)
        user.email = request.data.get('email', user.email)
        user.role = request.data.get('role', user.role)
        user.save()
        return Response({"message": f"User {user.email} updated successfully"})

class DailyReportView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        """Retrieve daily reports."""

        if is_admin(request.session.get('user_role')):
            # Admin can view all reports or filter by status
            status_filter = request.query_params.get('status')
            reports = DailyReport.objects.all()
            if status_filter:
                reports = reports.filter(status=status_filter)
        else:
            # Users can view only their own reports
            user_id = request.session.get('user_id')
            reports = DailyReport.objects.filter(user_id=user_id)

        serializer = DailyReportSerializer(reports, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        """Create a new daily report."""
        user_id = request.session.get('user_id')
        if not user_id:
            return Response({'error': 'User not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

        # Add user ID to the request data

        data = request.data
        data['user'] = user_id

        serializer = DailyReportSerializer(data=data)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, report_id):
        """Update a daily report."""
        user_role = request.session.get('user_role')
        user_id = request.session.get('user_id')
        try:
            report = DailyReport.objects.get(id=report_id)
        except DailyReport.DoesNotExist:
            return Response({'error': 'Report not found'}, status=status.HTTP_404_NOT_FOUND)

        # Check permissions
        if is_admin(user_role):
            # Admin can update status and admin_comments
            allowed_fields = ['status', 'admin_comments']
        elif user_id == report.user_id and report.status == 'pending':
            # Users can update their own reports only if still pending
            allowed_fields = [field.name for field in DailyReport._meta.fields if
                              field.name not in ['id', 'created_at', 'admin_comments']]

        else:
            raise PermissionDenied("You do not have permission to update this report.")

        # Update only allowed fields
        for field in allowed_fields:
            if field in request.data:
                setattr(report, field, request.data[field])
        report.save()

        serializer = DailyReportSerializer(report)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def delete(self, request, report_id):
        """Delete a daily report."""
        if not report_id:
            return Response({'error': 'Report ID is required'}, status=status.HTTP_400_BAD_REQUEST)

        user_role = request.session.get('user_role')
        user_id = request.session.get('user_id')
        try:
            report = DailyReport.objects.get(id=report_id)
        except DailyReport.DoesNotExist:
            return Response({'error': 'Report not found'}, status=status.HTTP_404_NOT_FOUND)

        # Check permissions
        if is_admin(user_role) or (user_id == report.user_id and report.status == 'pending'):
            report.delete()
            return Response({'message': 'Report deleted successfully'}, status=status.HTTP_200_OK)
        raise PermissionDenied("You do not have permission to delete this report.")


class ReportActionView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user_role = request.session.get('user_role')
        user_id = request.session.get('user_id')
        user = get_object_or_404(User, id=user_id)

        if not is_admin(user_role):
            raise PermissionDenied("Access denied")

        # Get the report ID, action (approved/denied), and admin comments from the request
        report_id = request.data.get('report_id')
        action = request.data.get('action')  # Action should be either 'approved' or 'denied'
        admin_comments = request.data.get('admin_comments')  # Admin comments (optional)

        if action not in ['approved', 'denied']:
            return Response({"error": "Invalid action"}, status=status.HTTP_400_BAD_REQUEST)

        # Fetch the report and update its status
        report = get_object_or_404(DailyReport, id=report_id)
        report.status = action
        report.admin_comments = admin_comments
        report.save()

        # Create an entry in the ApprovalHistory model with the correct action and comments
        ApprovalHistory.objects.create(
            report=report,
            action=action,
            performed_by=user,
            admin_comments=admin_comments  # Save the admin's comments
        )

        return Response({"message": f"Report {action} with comments: {admin_comments}"})


# class AcceptReportView(APIView):
#     permission_classes = [AllowAny]
#
#     def post(self, request):
#         user_role = request.session.get('user_role')
#         user_id = request.session.get('user_id')
#         user = get_object_or_404(User, id=user_id)
#
#         if not is_admin(user_role):
#             raise PermissionDenied("Access denied")
#         report_id = request.data.get('report_id')
#         report = get_object_or_404(DailyReport, id=report_id)
#         report.status = 'approved'
#         report.save()
#         ApprovalHistory.objects.create(report=report, action='approved', performed_by=user)
#         return Response({"message": "Report approved"})
#
# class DenyReportView(APIView):
#     permission_classes = [IsAuthenticated]
#
#     def post(self, request):
#         user_id = request.session.get('user_id')
#         if not is_admin(request.session.get('user_role')):
#             raise PermissionDenied("Access denied")
#         report_id = request.data.get('report_id')
#         report = get_object_or_404(DailyReport, id=report_id)
#         report.status = 'denied'
#         report.save()
#         ApprovalHistory.objects.create(report=report, action='denied', performed_by=user_id)
#         return Response({"message": "Report denied"})

class ApprovalHistoryView(APIView):

    authentication_classes = [SessionAuthentication]
    permission_classes = [IsAuthenticated]
    # permission_classes = [AllowAny]

    def get(self, request):
        user_id = request.session.get('user_id')
        if is_admin(request.session.get('user_role')):
            approvals = ApprovalHistory.objects.all()
        else:
            approvals = ApprovalHistory.objects.filter(report__user=user_id)
        return Response({"history": [{"id": a.id, "action": a.action, "report_id": a.report.id, "timestamp": a.timestamp} for a in approvals]})
