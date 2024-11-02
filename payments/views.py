from .serializers import (
    DepositSerializer,
    WalletSerializer,
    WalletTransactionSerializer,
)
from .models import Wallet, WalletTransaction
from useraccounts.models import UserEarnings
from useraccounts.serializers import UserEarningsSerializer
from rest_framework.generics import RetrieveAPIView, CreateAPIView
from rest_framework.views import APIView
from rest_framework.response import Response
from django.conf import settings
import requests
from rest_framework import status, permissions
from django.shortcuts import get_object_or_404
from rest_framework.permissions import IsAuthenticated
from django.core.cache import cache
import json
from decimal import Decimal


class WalletInfo(RetrieveAPIView):
    """
    View for getting wallet information.
    """

    serializer_class = WalletSerializer

    def get_object(self):
        return get_object_or_404(Wallet, user=self.request.user)


class DepositFunds(CreateAPIView):
    """
    View for depositing funds into the wallet.
    """

    serializer_class = DepositSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        response_data = serializer.save()
        return Response(response_data, status=status.HTTP_201_CREATED)


class VerifyDeposit(APIView):
    """
    View for verifying deposit.
    """

    def get(self, request, reference):
        """
        Verify deposit.
        :param request:
        :param reference:
        :return:
        """
        transaction = get_object_or_404(
            WalletTransaction,
            paystack_payment_reference=reference,
            wallet__user=request.user,
        )
        response = self._verify_transaction_with_paystack(reference)

        if response.status_code != 200:
            return Response(
                {"detail": "Failed to verify transaction with Paystack."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        resp_data = response.json()
        if resp_data.get("data", {}).get("status") == "success":
            self._update_transaction(transaction, resp_data)
            return Response(resp_data)

        return Response(resp_data, status=status.HTTP_400_BAD_REQUEST)

    def _verify_transaction_with_paystack(self, reference):
        url = f"https://api.paystack.co/transaction/verify/{reference}"
        headers = {"Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}"}
        return requests.get(url, headers=headers)

    def _update_transaction(self, transaction, resp_data):
        status = resp_data["data"]["status"]
        amount = resp_data["data"]["amount"]
        transaction.status = status
        transaction.amount = amount
        transaction.save()


class BankListView(APIView):
    def get(self, request):
        url = "https://api.paystack.co/bank"
        headers = {"Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}"}

        banks = cache.get("bank_list")
        if not banks:
            try:
                response = requests.get(url, headers=headers)
                response.raise_for_status()
                banks = response.json()
                cache.set("bank_list", banks, 60 * 60)
                return Response(response.json(), status=status.HTTP_200_OK)
            except requests.RequestException as e:
                return Response(
                    {"error": "Failed to fetch banks from Paystack", "details": str(e)},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

        return Response(banks, status=status.HTTP_200_OK)


class ListDepositTransactions(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        transactions = WalletTransaction.objects.filter(
            wallet__user=user, transaction_type="deposit"
        )
        serializer = WalletTransactionSerializer(transactions, many=True)
        return Response(serializer.data)


class VerifyBankAccountView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        account_number = request.query_params.get("account_number")
        bank_code = request.query_params.get("bank_code")

        if not account_number or not bank_code:
            return Response(
                {"error": "account_number and bank_code are required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        url = "https://api.paystack.co/bank/resolve"
        headers = {
            "Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}",
        }
        params = {
            "account_number": account_number,
            "bank_code": bank_code,
        }

        response = requests.get(url, headers=headers, params=params)

        if response.status_code == 200:
            return Response(response.json(), status=status.HTTP_200_OK)
        else:
            return Response(response.json(), status=response.status_code)


class ValidateAccountView(APIView):
    def post(self, request):
        bank_code = request.data.get("bank_code")
        account_number = request.data.get("account_number")

        # Get the cached bank list
        banks = cache.get("bank_list")
        if not banks:
            return Response(
                {"error": "Bank list not available"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        # Validate the bank code against the cached bank list
        bank = next((bank for bank in banks["data"] if bank["code"] == bank_code), None)
        if not bank:
            return Response(
                {"error": "Bank not found"}, status=status.HTTP_400_BAD_REQUEST
            )

        # Prepare the URL with query parameters
        url = f"https://api.paystack.co/bank/resolve?account_number={account_number}&bank_code={bank_code}"

        headers = {
            "Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}",
        }

        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            return Response(data)
        else:
            return Response(
                {"error": "Failed to validate account"}, status=response.status_code
            )


class PayoutView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        if user.is_staff == True:
            transactions = WalletTransaction.objects.all()
            serializer = WalletTransactionSerializer(transactions, many=True)
            return Response(serializer.data)
        transactions = WalletTransaction.objects.filter(wallet__user=user)
        transactions_data = WalletTransactionSerializer(transactions, many=True).data
        earnings = UserEarnings.objects.filter(individual_profile__user=user)
        earnings_data = UserEarningsSerializer(earnings, many=True).data
        all_data = transactions_data + earnings_data
        available_amount = 0
        for item in all_data:
            if item.get("transaction_type") != None and item.get("transaction_type") == "withdraw" and item.get("status") == "approved":
                available_amount -= Decimal(item["amount"])
            elif item.get("earnings_type") != None:
                available_amount += Decimal(item["amount"])
        return Response({"transaction_data": transactions_data,
                         "earning_data": earnings_data,
                         "available_amount": available_amount})

    def post(self, request):
        account_number = request.data.get("account_number")
        bank_code = request.data.get("bank_code")
        amount = request.data.get("amount")
        payment_method = request.data.get("payment_method")

        # Verify the account number with Paystack
        headers = {
            "Authorization": f"Bearer {settings.PAYSTACK_SECRET_KEY}",
        }
        verify_url = f"https://api.paystack.co/bank/resolve?account_number={account_number}&bank_code={bank_code}"
        response = requests.get(verify_url, headers=headers)
        data = response.json()

        if data["status"]:
            # Create a transaction record
            transaction = WalletTransaction.objects.create(
                transaction_type="withdraw",
                wallet= Wallet.objects.get(user=request.user),
                amount=amount
            )

            # Save the transaction details
            serializer = WalletTransactionSerializer(transaction)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response(
                {"error": "Account verification failed"},
                status=status.HTTP_400_BAD_REQUEST,
            )

class ApprovedPayoutView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        transactions = WalletTransaction.objects.filter(wallet__user=user, status="approved")
        serializer = WalletTransactionSerializer(transactions, many=True)
        return Response(serializer.data)
    
class UpdatePayoutStatus(APIView):
    permission_classes = [permissions.IsAdminUser]

    def post(self, request):
        body = json.loads(request.body)
        payoutId = body.get("payoutId")
        payoutStatus = body.get("status")
        if not payoutId or not payoutStatus:
            return Response({"message": "payoutId and status required"},status=status.HTTP_400_BAD_REQUEST)
        payout = get_object_or_404(WalletTransaction, pk=payoutId)
        payout.status = payoutStatus
        payout.save()
        return Response()

