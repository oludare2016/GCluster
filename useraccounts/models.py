from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin,
)
from django.db import models
from django.core.validators import FileExtensionValidator
from django.utils.translation import gettext_lazy as _
from .validators import validate_profile_picture
from .utils import calculate_and_create_bonuses


class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        """
        Create a new user with the given email and password.
        """
        if not email:
            raise ValueError(_("The Email field must be set"))
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        """
        Creates a superuser with the given email and password.
        """
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError(_("Superuser must have is_staff=True."))
        if extra_fields.get("is_superuser") is not True:
            raise ValueError(_("Superuser must have is_superuser=True."))

        return self.create_user(email, password, **extra_fields)


class CustomUser(AbstractBaseUser, PermissionsMixin):
    """
    Custom user model.
    """

    email = models.EmailField(unique=True)
    name = models.CharField(
        max_length=100
    )  # This will be used for both individual and company names
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    user_type = models.CharField(
        max_length=20,
        choices=[
            ("individual", "Individual"),
            ("company", "Company"),
            ("admin", "Admin"),
        ],
    )
    profile_picture = models.ImageField(
        upload_to="profile_pictures/",
        null=True,
        blank=True,
        validators=[
            validate_profile_picture,
            FileExtensionValidator(allowed_extensions=["png", "jpg", "jpeg", "tiff"]),
        ],
    )
    # Common fields
    phone_number = models.CharField(max_length=15, null=True, blank=True)
    address = models.CharField(max_length=255, null=True, blank=True)
    country = models.CharField(max_length=50, null=True, blank=True)
    state = models.CharField(max_length=50, null=True, blank=True)
    city = models.CharField(max_length=50, null=True, blank=True)
    date_joined = models.DateField(auto_now_add=True)
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("approved", "Approved"),
        ("rejected", "Rejected"),
    ]
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default="pending")

    objects = CustomUserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["name", "user_type"]

    class Meta:
        verbose_name = "Custom User"
        verbose_name_plural = "Custom Users"

    def save(self, *args, **kwargs):
        """
        Save the user model instance.
        """
        if self.pk:
            old_status = CustomUser.objects.get(pk=self.pk).status
            if old_status != "approved" and self.status == "approved":
                # Status has changed to approved
                sponsor = self.individual_profile.sponsor
                if sponsor:
                    calculate_and_create_bonuses(sponsor)
        super().save(*args, **kwargs)

    def __str__(self):
        """
        Return the email of the user.
        :return:
        """
        return self.email


class IndividualProfile(models.Model):
    """
    Individual profile model.
    """

    user = models.OneToOneField(
        CustomUser,
        on_delete=models.CASCADE,
        primary_key=True,
        related_name="individual_profile",
    )
    gender = models.CharField(
        max_length=10, choices=[("male", "Male"), ("female", "Female")]
    )
    sponsor = models.ForeignKey(
        CustomUser, on_delete=models.SET_NULL, null=True, related_name="sponsored"
    )
    POSITION_CHOICES = [
        ("left", "LEFT"),
        ("right", "Right"),
    ]
    position = models.CharField(max_length=20, choices=POSITION_CHOICES, default="left")
    RANK_CHOICES = [
        ("entrepreneur", "Entrepreneur"),
        ("field marshall", "Field Marshall"),
        ("business builder", "Business Builder"),
        ("board member", "Board Member"),
        ("brand ambassador", "Brand Ambassador"),
    ]
    rank = models.CharField(max_length=20, choices=RANK_CHOICES, default="entrepreneur")
    MEMBERSHIP_TYPE_CHOICES = [
        ("individual package", "Individual Package"),
    ]
    membership_type = models.CharField(
        max_length=20, choices=MEMBERSHIP_TYPE_CHOICES, default="individual package"
    )
    bank_code = models.CharField(max_length=50, null=True, blank=True)
    account_number = models.CharField(max_length=10, null=True, blank=True)
    account_name = models.CharField(max_length=50, null=True, blank=True)
    payment_method = models.CharField(max_length=50, null=True, blank=True)

    @property
    def total_earnings(self):
        """
        Calculate the total earnings for the individual profile.
        :return: Decimal total earnings
        """
        return self.earnings.aggregate(total=models.Sum("amount"))["total"] or 0.00

    class Meta:
        verbose_name = "Individual Profile"
        verbose_name_plural = "Individual Profiles"

    def __str__(self):
        """
        Return the name of the individual.
        :return:
        """
        return self.user.name


class CompanyProfile(models.Model):
    """
    Company profile model.
    """

    user = models.OneToOneField(
        CustomUser,
        on_delete=models.CASCADE,
        primary_key=True,
        related_name="company_profile",
    )
    company_registration_number = models.CharField(max_length=50)

    class Meta:
        verbose_name = "Company Profile"
        verbose_name_plural = "Company Profiles"

    def __str__(self):
        """
        Return the name of the company.
        :return:
        """
        return self.user.name


class EarningsType(models.Model):
    id = models.AutoField(primary_key=True)
    bonus_name = models.CharField(max_length=100, unique=True)
    created_on = models.DateTimeField(auto_now_add=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    STATUS_CHOICES = [
        ("enabled", "Enabled"),
        ("disabled", "Disabled"),
    ]
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default="enabled")

    class Meta:
        verbose_name = "Earnings Type"
        verbose_name_plural = "Earnings Types"

    def __str__(self):
        return f"{self.bonus_name} - {self.status}"


class UserEarnings(models.Model):
    """
    Earnings model to track earnings for individual profiles.
    """

    individual_profile = models.ForeignKey(
        IndividualProfile,
        on_delete=models.CASCADE,
        related_name="earnings",
    )
    amount = models.DecimalField(max_digits=10, decimal_places=2, default=0.00)
    description = models.CharField(max_length=255, null=True, blank=True)
    date = models.DateField(auto_now_add=True)
    earnings_type = models.ForeignKey(
        EarningsType, on_delete=models.SET_NULL, null=True, related_name="user_earnings"
    )

    class Meta:
        verbose_name = "User Earning"
        verbose_name_plural = "Users Earnings"

    def __str__(self):
        """
        Return a string representation of the earning.
        :return:
        """
        return f"{self.individual_profile.user.name} - {self.amount} on {self.date}"

    @property
    def earnings_type_name(self):
        return self.earnings_type.bonus_name if self.earnings_type else None
