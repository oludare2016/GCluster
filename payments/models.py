from django.db import models
from django.conf import settings
from django.utils import timezone
from django.contrib.auth import get_user_model
from uuid import uuid4


class Wallet(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, null=True, on_delete=models.CASCADE
    )
    currency = models.CharField(max_length=50, default="NGN")
    created_at = models.DateTimeField(default=timezone.now, null=True)

    class Meta:
        verbose_name = "Wallet"
        verbose_name_plural = "Wallets"

    def __str__(self):
        return self.user.__str__()


class WalletTransaction(models.Model):

    TRANSACTION_TYPES = (
        ("deposit", "deposit"),
        ("transfer", "transfer"),
        ("withdraw", "withdraw"),
    )
    wallet = models.ForeignKey(Wallet, null=True, on_delete=models.CASCADE)
    transaction_type = models.CharField(
        max_length=200, null=True, choices=TRANSACTION_TYPES
    )
    amount = models.DecimalField(max_digits=100, null=True, decimal_places=2)
    timestamp = models.DateTimeField(default=timezone.now, null=True)
    status = models.CharField(max_length=100, default="pending")
    paystack_payment_reference = models.CharField(
        max_length=100, default="", blank=True
    )

    class Meta:
        verbose_name = "Wallet Transaction"
        verbose_name_plural = "Wallet Transactions"

    def __str__(self):
        return self.wallet.user.__str__()


class Transaction(models.Model):
    uuid = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    STATUS_CHOICES = [
        ("approved", "Approved"),
        ("declined", "Declined"),
        ("pending", "Pending"),
    ]

    PAYMENT_METHOD_CHOICES = [
        ("bank_transfer", "Bank Transfer"),
        ("card", "Card"),
        # Add other payment methods here
    ]

    user = models.ForeignKey(get_user_model(), on_delete=models.CASCADE)
    reference_id = models.CharField(max_length=100, unique=True)
    date = models.DateTimeField(auto_now_add=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    payment_method = models.CharField(max_length=50, choices=PAYMENT_METHOD_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")

    class Meta:
        verbose_name = "Transaction"
        verbose_name_plural = "Transactions"

    def __str__(self):
        return f"Transaction {self.reference_id} - {self.status}"
