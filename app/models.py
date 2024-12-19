from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    # Add custom fields here if needed
    class Meta:
        db_table = 'abs_users'  # Explicitly specify the table name

    email = models.EmailField(unique=True)  # Ensure email is unique
    phone_number = models.CharField(max_length=10, blank=True, null=True)
    role = models.CharField(max_length=5, choices=[('admin', 'Admin'), ('user', 'User')], default='user')

    def __str__(self):
        return self.username


class DailyReport(models.Model):


    class Meta:
        db_table = 'abs_dailyreport'  # Explicitly specify the table name
    # User and report details
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    report_date = models.DateField()
    status = models.CharField(
        max_length=10,
        choices=[('pending', 'Pending'), ('approved', 'Approved'), ('denied', 'Denied')],
        default='pending'
    )
    admin_comments = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    # Broiler bird details
    broiler_opening_stock = models.IntegerField()  # Birds at the start of the day
    broiler_closing_stock = models.IntegerField()  # Birds left at the end of the day
    broiler_sold_customer = models.IntegerField()  # Birds sold to customers
    broiler_sold_b2b = models.IntegerField()  # Birds sold for B2B
    broiler_dead = models.IntegerField()  # Birds that died during the day
    broiler_wastage_weight = models.FloatField()  # Wastage weight in kg
    broiler_rate_customer = models.FloatField()  # Rate per bird for customers
    broiler_rate_b2b = models.FloatField()  # Rate per bird for B2B
    broiler_total_sales = models.IntegerField()  # Total birds sold (customer + B2B)

    # Country bird details
    country_opening_stock = models.IntegerField()
    country_closing_stock = models.IntegerField()
    country_sold_customer = models.IntegerField()
    country_sold_b2b = models.IntegerField()
    country_dead = models.IntegerField()
    country_wastage_weight = models.FloatField()
    country_rate_customer = models.FloatField()
    country_rate_b2b = models.FloatField()
    country_total_sales = models.IntegerField()

    # Goat details
    goat_opening_stock = models.IntegerField()
    goat_sold_customer = models.IntegerField()
    mutton_total_weight = models.FloatField()  # Total weight of goats in kg

    # Mutton details
    mutton_weight_sold_customer = models.FloatField()
    mutton_weight_sold_b2b = models.FloatField()
    mutton_wastage_weight = models.FloatField()
    mutton_rate_customer = models.FloatField()
    mutton_rate_b2b = models.FloatField()

    # Egg details
    egg_opening_stock = models.IntegerField()
    egg_sold = models.IntegerField()
    egg_closing_stock = models.IntegerField()
    egg_rate = models.FloatField()

    # Payment details
    total_offline_amount = models.FloatField()
    total_online_amount = models.FloatField()
    total_sales_amount = models.FloatField()


class ApprovalHistory(models.Model):
    report = models.ForeignKey(DailyReport, on_delete=models.CASCADE)
    action = models.CharField(max_length=10, choices=[('approved', 'Approved'), ('denied', 'Denied')])
    performed_by = models.ForeignKey(User, on_delete=models.CASCADE)
    admin_comments = models.TextField(blank=True, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)
