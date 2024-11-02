from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    IndividualProfileViewSet,
    CompanyProfileViewSet,
    CustomTokenObtainPairView,
    SignupView,
    UserEarningsView,
    PasswordResetView,
    PasswordResetRequestView,
    EarningTypesViewSet,
    AllEarningsViewSet,
    PasswordUpdateView
)
from rest_framework_simplejwt.views import (
    TokenRefreshView,
)

router = DefaultRouter()
router.register(r"individuals", IndividualProfileViewSet, basename="individuals")
router.register(r"companies", CompanyProfileViewSet, basename="companies")
router.register(r"earnings", AllEarningsViewSet, basename="earnings")
router.register("earning-types", EarningTypesViewSet, basename="earning-types")

urlpatterns = [
    path("", include(router.urls)),
    path("token/", CustomTokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("signup/", SignupView.as_view(), name="signup"),
    path(
        "user-earnings/<int:user_id>/", UserEarningsView.as_view(), name="user_earnings"
    ),
    path(
        "password/reset/",
        PasswordResetRequestView.as_view(),
        name="password-reset-request",
    ),
    path(
        "password/reset/<str:uidb64>/<str:token>/",
        PasswordResetView.as_view(),
        name="password-reset",
    ),
    path(
        "password_update/",
        PasswordUpdateView.as_view(),
        name="password-update",
    ),
]
