from django.contrib import admin
from .models import Wallet, WalletTransaction, Transaction


@admin.register(Wallet)
class WalletAdmin(admin.ModelAdmin):
    list_display = ("user", "currency", "created_at")


@admin.register(WalletTransaction)
class WalletTransactionAdmin(admin.ModelAdmin):
    list_display = ("wallet", "transaction_type", "amount", "timestamp", "status")


@admin.register(Transaction)
class TransactionAdmin(admin.ModelAdmin):
    list_display = ("user", "reference_id", "amount", "payment_method", "status")

    def get_queryset(self, request):
        return Transaction.objects.filter(user=request.user)
