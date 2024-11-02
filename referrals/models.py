from django.db import models
from uuid import uuid4
from django.core.validators import MaxValueValidator, FileExtensionValidator
from .validators import validate_file_size
from django.conf import settings
from useraccounts.models import CustomUser
from django.contrib.auth import get_user_model


class Product(models.Model):
    """
    Product model.
    """

    uuid = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    product_name = models.CharField(max_length=255)
    company = models.ForeignKey(
        CustomUser, on_delete=models.CASCADE, related_name="products"
    )
    date_created = models.DateTimeField(auto_now_add=True)
    date_updated = models.DateTimeField(auto_now=True)
    description = models.TextField()
    product_image = models.ImageField(
        blank=True,
        null=True,
        upload_to="product_images/",
        validators=[
            FileExtensionValidator(allowed_extensions=["png", "jpg", "jpeg", "tiff"]),
            validate_file_size,
        ],
    )
    product_value = models.PositiveIntegerField(
        default=0, validators=[MaxValueValidator(1_000_000_000)]
    )
    product_link = models.CharField(max_length=255)
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("active", "Active"),
        ("declined", "Declined"),
    ]
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default="pending")
    LINK_CHOICES = [
        ("whatsapp", "Whatsapp"),
        ("website", "Website"),
        ("phone", "Phone"),
    ]
    product_link_type = models.CharField(max_length=20, choices=LINK_CHOICES, default="website")
    shares = models.PositiveIntegerField(
        default=0, validators=[MaxValueValidator(1_000_000_000)]
    )
    traffic = models.PositiveIntegerField(
        default=0, validators=[MaxValueValidator(1_000_000_000)]
    )
    pending_shares = models.PositiveIntegerField(default=0)

    class Meta:
        """
        Meta class for the Product model.
        """

        verbose_name = "Product"
        verbose_name_plural = "Products"

    def __str__(self):
        """
        Returns a string representation of the Product object.

        :return: The name of the product.
        :rtype: str
        """
        return self.product_name


class SupportTicket(models.Model):
    """
    A model representing a support ticket.
    """

    uuid = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    date_created = models.DateTimeField(auto_now_add=True)
    date_updated = models.DateTimeField(auto_now=True)
    submitted_by = models.ForeignKey(
        CustomUser, on_delete=models.CASCADE, related_name="support_tickets"
    )
    SUPPORT_CHOICES = [
        ("support", "Support"),
        ("suggestion", "Suggestion"),
    ]
    support = models.CharField(
        max_length=15, choices=SUPPORT_CHOICES, default="support"
    )
    title = models.CharField(max_length=255)
    description = models.TextField()
    STATUS_CHOICES = [
        ("in-progress", "In Progress"),
        ("resolved", "Resolved"),
    ]
    status = models.CharField(
        max_length=15, choices=STATUS_CHOICES, default="in-progress"
    )
    PRIORITY_CHOICES = [
        ("high", "High"),
        ("medium", "Medium"),
        ("low", "Low"),
    ]
    priority = models.CharField(max_length=15, choices=PRIORITY_CHOICES, default="low")
    attachments = models.FileField(
        blank=True,
        null=True,
        upload_to="support_ticket_attachments/",
        validators=[
            FileExtensionValidator(
                allowed_extensions=["png", "jpg", "jpeg", "tiff", "pdf"]
            ),
            validate_file_size,
        ],
    )

    def save(self, *args, **kwargs):
        """
        Save the object to the database.

        This method is called when an instance of the class is saved to the database. It generates a UUID for the object if it doesn't already have one and then calls the `save` method of the parent class.

        Parameters:
            *args: Variable length argument list.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            None
        """
        if not self.uuid:
            self.uuid = uuid4()
        super().save(*args, **kwargs)

    class Meta:
        """
        Meta class for the SupportTicket model.
        """

        verbose_name = "Support Ticket"
        verbose_name_plural = "Support Tickets"

    def __str__(self):
        """
        Returns a string representation of the object.

        :return: The title of the object.
        :rtype: str
        """
        return self.title


class TicketReply(models.Model):
    uuid = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    ticket = models.ForeignKey(
        SupportTicket, on_delete=models.CASCADE, related_name="replies"
    )
    replied_by = models.ForeignKey(
        CustomUser, on_delete=models.CASCADE, related_name="ticket_replies"
    )
    reply_text = models.TextField()
    date_created = models.DateTimeField(auto_now_add=True)
    attachment = models.FileField(
        upload_to="ticket_reply_attachments/",
        null=True,
        blank=True,
        validators=[
            FileExtensionValidator(
                allowed_extensions=["jpg", "jpeg", "png", "pdf", "doc", "docx"]
            )
        ],
    )

    class Meta:
        verbose_name = "Ticket Reply"
        verbose_name_plural = "Ticket Replies"

    @property
    def get_replies(self):
        return self.replies.all().order_by("-date_created")

    def __str__(self):
        return f"Reply to {self.ticket.title} by {self.replied_by.name}"


class UserRanking(models.Model):
    """
    User ranking model for the referral program.
    """

    icon = models.ImageField(
        upload_to="ranking_icons/",
        validators=[validate_file_size],
        blank=True,
        null=True,
    )
    user = models.CharField(max_length=255, blank=True, null=True)
    rank_level = models.IntegerField(default=0)
    NAME_CHOICES = [
        ("gold pro", "Gold Pro"),
        ("gold", "Gold"),
        ("silver pro", "Silver Pro"),
        ("silver", "Silver"),
        ("platinum", "Platinum"),
    ]
    name = models.CharField(max_length=15, choices=NAME_CHOICES, default="silver")
    total_recruits = models.IntegerField(default=0)
    bonus = models.IntegerField(default=0)
    STATUS_CHOICES = [
        ("enabled", "Enabled"),
        ("disabled", "Disabled"),
    ]
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default="enabled")
    date = models.DateTimeField(auto_now_add=True)

    class Meta:
        """
        Meta class for the UserRanking model.
        """

        verbose_name = "User Ranking"
        verbose_name_plural = "User Rankings"

    def __str__(self):
        """
        Returns a string representation of the object.
        :return: The title of the object.
        :rtype: str
        """
        return self.name


class Staff(models.Model):
    """
    Staff model for the referral program.
    """

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="staff_profile"
    )
    role = models.CharField(
        max_length=20,
        choices=[
            ("admin", "Admin"),
            ("superadmin", "Superadmin"),
        ],
    )

    class Meta:
        """
        Meta class for the Staff model.
        """

        verbose_name = "Staff"
        verbose_name_plural = "Staff"

    def __str__(self):
        """
        Returns a string representation of the object.

        :return: A string containing the first name and last name of the object.
        :rtype: str
        """
        return self.user.name

    @property
    def full_name(self):
        """
        Returns the full name of the object as a string.

        :return: A string containing the first name and last name of the object.
        :rtype: str
        """
        return self.user.name

    @property
    def email(self):
        """
        Returns the email address associated with the user object.

        :return: The email address of the user.
        :rtype: str
        """
        return self.user.email

    @property
    def is_active(self):
        """
        Returns whether the user associated with this staff member is active or not.

        :return: A boolean indicating whether the user is active or not.
        :rtype: bool
        """
        return self.user.is_active

    @property
    def is_superuser(self):
        return self.role == "superadmin"

    def enable(self):
        """
        Enables the user associated with this staff member.

        This function sets the `is_active` attribute of the user object to `True` and saves the changes to the database.

        Parameters:
            self (Staff): The staff object.

        Returns:
            None
        """
        self.user.is_active = True
        self.user.save()

    def disable(self):
        """
        Disables the user associated with this staff member.

        This function sets the `is_active` attribute of the user object to `False` and saves the changes to the database.

        Parameters:
            self (Staff): The staff object.

        Returns:
            None
        """
        self.user.is_active = False
        self.user.save()


class ShareRequest(models.Model):
    """
    Share request model for the referral program.
    """

    user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE)
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    date_requested = models.DateTimeField(auto_now_add=True)
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("approved", "Approved"),
        ("rejected", "Rejected"),
    ]
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default="pending")

    class Meta:
        verbose_name = "Share Request"
        verbose_name_plural = "Share Requests"

    def __str__(self):
        return f"{self.user.name} - {self.product.product_name} - {self.status}"
