from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    ProductViewSet,
    SupportTicketViewSet,
    UserRankingViewSet,
    VerifyAccountView,
    StaffViewSet,
    SupportTicketReplyViewSet,
    ReferralIndividualProfileViewSet,
    ShareProductView,
    ShareRequestView,
    ShareApprovalView,
)

router = DefaultRouter()
router.register(r"products", ProductViewSet)
router.register(r"supporttickets", SupportTicketViewSet)
router.register(
    r"supportticketreplies",
    SupportTicketReplyViewSet,
    basename="support-ticket-replies",
)
router.register(r"userrankings", UserRankingViewSet)
router.register(r"staff", StaffViewSet)
router.register(
    r"individuals", ReferralIndividualProfileViewSet, basename="referral-individuals"
)

urlpatterns = [
    path("", include(router.urls)),
    path("verify/", VerifyAccountView.as_view(), name="verify-account"),
    path("product/share/", ShareProductView.as_view(), name="share-product"),
    path("product/share-request/", ShareRequestView.as_view(), name="share-request"),
    path("product/share-approval/", ShareApprovalView.as_view(), name="share-approval"),
]
