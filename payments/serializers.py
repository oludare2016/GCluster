from .models import Wallet, WalletTransaction, Transaction
from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.conf import settings
from django.db.models import Sum

import requests

User = get_user_model()


class WalletSerializer(serializers.ModelSerializer):
    """
    Serializers to validate the user's wallet
    """

    balance = serializers.SerializerMethodField()

    def get_balance(self, obj):
        bal = WalletTransaction.objects.filter(wallet=obj, status="success").aggregate(
            Sum("amount")
        )["amount__sum"]
        return bal

    class Meta:
        model = Wallet
        fields = ["id", "currency", "balance"]


def is_amount(value):
    if value <= 0:
        raise serializers.ValidationError({"detail": "Invalid Amount"})
    return value


class DepositSerializer(serializers.Serializer):

    amount = serializers.IntegerField(validators=[is_amount])
    email = serializers.EmailField()

    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            return value
        raise serializers.ValidationError({"detail": "Email not found"})

    def save(self):
        user = self.context["request"].user
        wallet = Wallet.objects.get(user=user)
        data = self.validated_data
        url = "https://api.paystack.co/transaction/initialize"
        headers = {"authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}"}
        r = requests.post(url, headers=headers, data=data)
        response = r.json()
        WalletTransaction.objects.create(
            wallet=wallet,
            transaction_type="deposit",
            amount=data["amount"],
            paystack_payment_reference=response["data"]["reference"],
            status="pending",
        )

        return response


class WalletTransactionSerializer(serializers.ModelSerializer):
    class Meta:
        model = WalletTransaction
        fields = [
            "id",
            "amount",
            "paystack_payment_reference",
            "status",
            "timestamp",
            "transaction_type",
            "username",
            "user_picture",
            "bank_code",
            "account_number",
            "account_name",
            "email"
        ]
    username = serializers.CharField(source="wallet.user.name", required=False)
    user_picture = serializers.CharField(source="wallet.user.profile_picture", required=False)
    bank_code = serializers.CharField(source="wallet.user.individual_profile.bank_code", required=False)
    account_number = serializers.CharField(source="wallet.user.individual_profile.account_number", required=False)
    account_name = serializers.CharField(source="wallet.user.individual_profile.account_name", required=False)
    email = serializers.CharField(source="wallet.user.email", required=False)


class TransactionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Transaction
        fields = "__all__"
