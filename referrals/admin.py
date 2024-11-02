from django.contrib import admin

from .models import Product, SupportTicket, UserRanking, Staff, ShareRequest


@admin.register(Product)
class ProductAdmin(admin.ModelAdmin):
    """
    Admin class for the Product model.
    """

    list_display = ["product_name", "company", "date_created", "date_updated"]
    list_filter = ["company"]


@admin.register(SupportTicket)
class SupportTicketAdmin(admin.ModelAdmin):
    """
    Admin class for the SupportTicket model.
    """

    list_display = ["title", "submitted_by", "date_created", "date_updated"]
    list_filter = ["support", "status", "priority"]


@admin.register(UserRanking)
class UserRankingAdmin(admin.ModelAdmin):
    """
    Admin class for the UserRanking model.
    """

    list_display = ["rank_level", "status", "name", "total_recruits", "bonus"]
    list_filter = ["name"]


@admin.register(Staff)
class StaffAdmin(admin.ModelAdmin):
    """
    Admin class for the Staff model.
    """

    list_display = ["user", "role"]
    list_filter = ["role"]


@admin.register(ShareRequest)
class ShareRequestAdmin(admin.ModelAdmin):
    """
    Admin class for the ShareRequest model.
    """

    list_display = ["user", "product", "status"]
    list_filter = ["status"]
