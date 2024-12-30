from django.contrib.auth.hashers import check_password
from django.core.exceptions import PermissionDenied
from django.db import IntegrityError
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.exceptions import PermissionDenied, NotFound
from rest_framework.permissions import AllowAny
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken

from .models import DailyReport, ApprovalHistory
from .models import User
from .serializers import DailyReportSerializer


# Helper function for role-based access control
def is_admin(user_role):
    return user_role == 'admin'

def get_users():
    users = User.objects.all()

    userData = [
        {
            "user_id": user.id,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "role": user.role,
            "phone_number": user.phone_number,
       } for user in users
    ]
    return userData

def get_approved_reports(user):
    if user.role == 'admin':
        # Admins can view all approval histories
        approvals = ApprovalHistory.objects.all()
    else:
        # Non-admin users can only view their own approval histories
        approvals = ApprovalHistory.objects.filter(report__user=user.id)

    # Format the approval history response
    history = [
        {
            "id": a.id,
            "action": a.action,
            "report_id": a.report.id,
            "approved_by": a.performed_by.first_name,
            "timestamp": a.timestamp,
            "admin_comments": a.admin_comments,
        }
        for a in approvals
    ]
    return history

def get_reports(user):

    # Fetch all reports that are approved and submitted by the logged-in user
    if is_admin(user.role):
        reports = DailyReport.objects.all()
    else:
        reports = DailyReport.objects.filter(user_id=user.id)

    user_details = get_users()
    user_lookup = {user['user_id']: user for user in user_details}

    # Prepare the report details to return
    report_details = [
        {
            "id": report.id,
            "user": user_lookup.get(report.user_id, {}).get("first_name", "Unknown"),
            "report_date": report.report_date,
            "status": report.status,
            "admin_comments": report.admin_comments,
            "created_at": report.created_at,
            "broiler_opening_stock": report.broiler_opening_stock,
            "broiler_closing_stock": report.broiler_closing_stock,
            "broiler_sold_customer": report.broiler_sold_customer,
            "broiler_sold_b2b": report.broiler_sold_b2b,
            "broiler_dead": report.broiler_dead,
            "broiler_wastage_weight": report.broiler_wastage_weight,
            "broiler_rate_customer": report.broiler_rate_customer,
            "broiler_rate_b2b": report.broiler_rate_b2b,
            "broiler_total_sales": report.broiler_total_sales,
            "country_opening_stock": report.country_opening_stock,
            "country_closing_stock": report.country_closing_stock,
            "country_sold_customer": report.country_sold_customer,
            "country_sold_b2b": report.country_sold_b2b,
            "country_dead": report.country_dead,
            "country_wastage_weight": report.country_wastage_weight,
            "country_rate_customer": report.country_rate_customer,
            "country_rate_b2b": report.country_rate_b2b,
            "country_total_sales": report.country_total_sales,
            "goat_opening_stock": report.goat_opening_stock,
            "goat_sold_customer": report.goat_sold_customer,
            "mutton_total_weight": report.mutton_total_weight,
            "mutton_weight_sold_customer": report.mutton_weight_sold_customer,
            "mutton_weight_sold_b2b": report.mutton_weight_sold_b2b,
            "mutton_wastage_weight": report.mutton_wastage_weight,
            "mutton_rate_customer": report.mutton_rate_customer,
            "mutton_rate_b2b": report.mutton_rate_b2b,
            "egg_opening_stock": report.egg_opening_stock,
            "egg_sold": report.egg_sold,
            "egg_closing_stock": report.egg_closing_stock,
            "egg_rate": report.egg_rate,
            "total_offline_amount": report.total_offline_amount,
            "total_online_amount": report.total_online_amount,
            "total_sales_amount": report.total_sales_amount,
        }
        for report in reports
    ]

    return report_details

class LoginView(APIView):
    permission_classes = [AllowAny]  # Allow unauthenticated users to access this endpoint

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')  # User-input plain password

        if not email:
            return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.get(email=email)  # Fetch user by email

        # Use check_password to compare user-input password with database password
        if check_password(password, user.password):
            request.session['user_id'] = user.id
            request.session['user_email'] = user.email
            request.session['user_role'] = user.role
            request.session['user_phone_number'] = user.phone_number

            # Generate JWT token
            refresh = RefreshToken.for_user(user)

            # Prepare user details
            user_details = {
                'id': str(user.id),
                'name': user.first_name,
                'phone_number': user.phone_number if user.phone_number else "Not Provided",
                'role': user.role,
            }

            # Return response with user details and tokens
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'user': user_details,
                'reports': get_reports(user),
                'history': get_approved_reports(user)
            })

        else:
            return Response({"error": "Invalid credentials"}, status=401)


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

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # The authenticated user is available in request.user
        user = request.user

        if not user or not user.is_authenticated:
            raise PermissionDenied("Authentication credentials were not provided.")

        # Get the new password from the request
        new_password = request.data.get('new_password')

        if not new_password:
            return Response({"error": "New password is required."}, status=400)

        # Update the user's password
        user.set_password(new_password)
        user.save()

        return Response({"message": "Password updated successfully."})

class RegisterUserView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # Ensure the authenticated user has the 'admin' role
        if not request.user.role == 'admin':
            raise PermissionDenied("Access denied: Only admins can register new users.")

        # Extract data from the request
        email = request.data.get('email')
        password = request.data.get('password')
        role = request.data.get('role', 'user')
        first_name = request.data.get('first_name')
        last_name = request.data.get('last_name')
        phone_number = request.data.get('phone_number')

        try:
            # Check if a user with the same email already exists
            if User.objects.filter(email=email).exists():
                return Response(
                    {"error": f"User with email {email} already exists"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Create a new user
            user = User.objects.create_user(
                username=email,
                email=email,
                password=password,
                role=role,
                first_name=first_name,
                last_name=last_name,
                phone_number=phone_number,
            )

            return Response(
                {"message": f"User {email} with ID {user.id} registered successfully."},
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
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """Retrieve daily reports."""
        user = request.user

        if user.role == 'admin':
            # Admin can view all reports or filter by status
            status_filter = request.query_params.get('status')
            reports = DailyReport.objects.all()
            if status_filter:
                reports = reports.filter(status=status_filter)
        else:
            # Users can view only their own reports
            reports = DailyReport.objects.filter(user_id=user.id)

        serializer = DailyReportSerializer(reports, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        """Create a new daily report."""
        user = request.user

        # Add user ID to the request data
        data = request.data
        data['user'] = user.id

        serializer = DailyReportSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, report_id):
        """Delete a daily report."""
        user = request.user

        try:
            report = DailyReport.objects.get(id=report_id)
        except DailyReport.DoesNotExist:
            return Response({'error': 'Report not found'}, status=status.HTTP_404_NOT_FOUND)

        # Check permissions
        if user.role == 'admin' or (user.id == report.user_id and report.status == 'pending'):
            report.delete()
            return Response({'message': 'Report deleted successfully'}, status=status.HTTP_200_OK)
        raise PermissionDenied("You do not have permission to delete this report.")


class UpdateReportView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def put(self, request, report_id):
        """Update a daily report."""
        user = request.user

        # Fetch the report
        try:
            report = DailyReport.objects.get(id=report_id)
        except DailyReport.DoesNotExist:
            raise NotFound("Report not found")

        # Determine permissions
        if user.role == 'admin':
            # Admins can update `status` and `admin_comments`
            allowed_fields = ['status', 'admin_comments']
        elif user.id == report.user_id and (report.status in ['pending', 'denied']):
            # Users can update their own reports only if status is 'pending' or 'denied'
            allowed_fields = [
                field.name for field in DailyReport._meta.fields
                if field.name not in ['id', 'created_at', 'admin_comments', 'user_id']
            ]
        else:
            raise PermissionDenied("You do not have permission to update this report.")

        # Ensure `user` is set to `request.user.id`
        request.data['user'] = user

        # Update only the allowed fields
        for field in allowed_fields:
            if field in request.data:
                setattr(report, field, request.data[field])

        try:
            report.save()
        except Exception as e:
            print(f"Error saving report: {e}")
            return Response({'error': 'Failed to update the report'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Serialize and return the updated report
        serializer = DailyReportSerializer(report)
        return Response(serializer.data, status=status.HTTP_200_OK)


class ReportActionView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # Ensure the user exists
        user = get_object_or_404(User, id=request.user.id)

        # Verify if the user is an admin
        if not is_admin(user.role):
            raise PermissionDenied("Access denied")

        # Extract report ID, action, and admin comments from the request
        report_id = request.data.get('report_id')
        action = request.data.get('action')  # Expected values: 'approved' or 'denied'
        admin_comments = request.data.get('admin_comments')  # Optional admin comments

        if not report_id:
            return Response({"error": "Report ID is required"}, status=status.HTTP_400_BAD_REQUEST)

        if action not in ['approved', 'denied']:
            return Response({"error": "Invalid action. Use 'approved' or 'denied'."}, status=status.HTTP_400_BAD_REQUEST)

        # Fetch the report and update its status
        try:
            report = DailyReport.objects.get(id=report_id)
        except DailyReport.DoesNotExist:
            raise NotFound("Report not found")

        report.status = action
        report.admin_comments = admin_comments
        report.save()

        # Log the action in the ApprovalHistory model
        ApprovalHistory.objects.create(
            report=report,
            action=action,
            performed_by=user,
            admin_comments=admin_comments
        )

        # Prepare the response
        return Response(
            {"message": f"Report {action} successfully", "admin_comments": admin_comments},
            status=status.HTTP_200_OK
        )


class ApprovalHistoryView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):

        # Check if the authenticated user is an admin
        return Response({"history": get_approved_reports(request.user)})


class ApprovedReportsByUserView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Get the logged-in user
        user = request.user

        # Fetch all reports that are approved and submitted by the logged-in user
        reports = DailyReport.objects.filter(user_id=user.id, status="approved")

        # Prepare the report details to return
        report_details = [
            {
                "id": report.id,
                "report_date": report.report_date,
                "status": report.status,
                "admin_comments": report.admin_comments,
                "created_at": report.created_at,
                "broiler_opening_stock": report.broiler_opening_stock,
                "broiler_closing_stock": report.broiler_closing_stock,
                "broiler_sold_customer": report.broiler_sold_customer,
                "broiler_sold_b2b": report.broiler_sold_b2b,
                "broiler_dead": report.broiler_dead,
                "broiler_wastage_weight": report.broiler_wastage_weight,
                "broiler_rate_customer": report.broiler_rate_customer,
                "broiler_rate_b2b": report.broiler_rate_b2b,
                "broiler_total_sales": report.broiler_total_sales,
                "country_opening_stock": report.country_opening_stock,
                "country_closing_stock": report.country_closing_stock,
                "country_sold_customer": report.country_sold_customer,
                "country_sold_b2b": report.country_sold_b2b,
                "country_dead": report.country_dead,
                "country_wastage_weight": report.country_wastage_weight,
                "country_rate_customer": report.country_rate_customer,
                "country_rate_b2b": report.country_rate_b2b,
                "country_total_sales": report.country_total_sales,
                "goat_opening_stock": report.goat_opening_stock,
                "goat_sold_customer": report.goat_sold_customer,
                "mutton_total_weight": report.mutton_total_weight,
                "mutton_weight_sold_customer": report.mutton_weight_sold_customer,
                "mutton_weight_sold_b2b": report.mutton_weight_sold_b2b,
                "mutton_wastage_weight": report.mutton_wastage_weight,
                "mutton_rate_customer": report.mutton_rate_customer,
                "mutton_rate_b2b": report.mutton_rate_b2b,
                "egg_opening_stock": report.egg_opening_stock,
                "egg_sold": report.egg_sold,
                "egg_closing_stock": report.egg_closing_stock,
                "egg_rate": report.egg_rate,
                "total_offline_amount": report.total_offline_amount,
                "total_online_amount": report.total_online_amount,
                "total_sales_amount": report.total_sales_amount,
            }
            for report in reports
        ]

        return Response({"approved_reports": report_details})

class GetReportsView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({"reports": get_reports(request.user)})