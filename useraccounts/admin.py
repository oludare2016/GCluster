from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import (
    CustomUser,
    IndividualProfile,
    CompanyProfile,
    UserEarnings,
    EarningsType,
)
from .forms import UserCreationForm, UserChangeForm


class UserAdmin(BaseUserAdmin):
    """
    Define admin model for custom User model with no email field
    """

    form = UserChangeForm
    add_form = UserCreationForm

    list_display = ("email", "name", "user_type", "is_staff", "is_active")
    list_filter = ("user_type", "is_staff", "is_active")
    fieldsets = (
        (None, {"fields": ("email", "password")}),
        (
            "Personal Info",
            {
                "fields": (
                    "name",
                    "user_type",
                    "profile_picture",
                    "status",
                    "phone_number",
                    "address",
                    "country",
                    "state",
                    "city",
                )
            },
        ),
        ("Permissions", {"fields": ("is_staff", "is_active", "is_superuser")}),
        ("Important dates", {"fields": ("last_login",)}),
    )
    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": (
                    "email",
                    "name",
                    "user_type",
                    "profile_picture",
                    "password1",
                    "password2",
                    "is_staff",
                    "is_active",
                ),
            },
        ),
    )
    search_fields = ("email",)
    ordering = ("email",)


admin.site.register(CustomUser, UserAdmin)


@admin.register(CompanyProfile)
class CompanyProfileAdmin(admin.ModelAdmin):
    """
    Admin class for the CompanyProfile model.
    """

    list_display = (
        "user",
        "company_registration_number",
    )


@admin.register(IndividualProfile)
class IndividualProfileAdmin(admin.ModelAdmin):
    """
    Admin class for the IndividualProfile model.
    """

    list_display = (
        "user",
        "gender",
        "sponsor",
        "rank",
        "membership_type",
        "total_earnings",
    )


@admin.register(UserEarnings)
class UserEarningsAdmin(admin.ModelAdmin):
    """
    Admin class for the UserEarnings model.
    """

    list_display = ("individual_profile", "amount", "date")


@admin.register(EarningsType)
class EarningsTypeAdmin(admin.ModelAdmin):
    """
    Admin class for the EarningsType model.
    """

    list_display = ("bonus_name", "status")
