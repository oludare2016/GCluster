from django.utils.dateparse import parse_date
from rest_framework import viewsets, generics, permissions
from rest_framework.views import APIView
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from .models import IndividualProfile, CompanyProfile, UserEarnings, EarningsType, CustomUser
from payments.models import Wallet, WalletTransaction
from .serializers import (
    IndividualProfileSerializer,
    CompanyProfileSerializer,
    CustomUserSerializer,
    UserEarningsSerializer,
    CustomUserTokenObtainPairSerializer,
    SignupSerializer,
    PasswordResetSerializer,
    EarningsTypeSerializer,
)
from django.db.models import Sum
from django.utils import timezone
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str
from django.contrib.auth import get_user_model
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode
from django.core.mail import EmailMessage
from rest_framework.decorators import action
import json
import datetime
from datetime import timedelta, date
from django.conf import settings

User = get_user_model()


class SignupView(generics.CreateAPIView):
    """
    API endpoint that allows users to signup.
    """

    serializer_class = SignupSerializer
    authentication_classes = []
    permission_classes = [AllowAny]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        refresh = RefreshToken.for_user(user)

        response_data = {
            "user_id": user.id,
            "email": user.email,
            "name": user.name,
            "user_type": user.user_type,
            "phone_number": user.phone_number,
            "address": user.address,
            "country": user.country,
            "state": user.state,
            "city": user.city,
            "date_joined": user.date_joined,
            "status": user.status,
            "profile_picture": (
                user.profile_picture.url if user.profile_picture else None
            ),
            "refresh": str(refresh),
            "access": str(refresh.access_token),
        }

        request = self.request
        sponsor_id = request.user.id if request.user.is_authenticated else None

        if user.user_type == "individual":
            profile = IndividualProfile.objects.get(user=user)
            response_data.update(
                {
                    "gender": profile.gender,
                    "sponsor_id": profile.sponsor_id,
                    "rank": profile.rank,
                    "total_earnings": profile.total_earnings,
                }
            )
        elif user.user_type == "company":
            profile = CompanyProfile.objects.get(user=user)
            response_data.update(
                {
                    "company_registration_number": profile.company_registration_number,
                }
            )

        return Response(response_data, status=status.HTTP_201_CREATED)

def get_sponsees_and_their_sponsees(user):
  sponsees = IndividualProfile.objects.filter(sponsor=user, user__status="approved")
  result = []
  for sponsee in sponsees:
    user = CustomUser.objects.get(email=sponsee.user.email)
    sub_sponsees = get_sponsees_and_their_sponsees(user)
    result.extend(sub_sponsees)
    result.append(sponsee)  
  return result

rank_hash_table = {
     100: {"name": "field marshal", "value": 2},
     500: {"name": "businesss builder", "value": 5},
     2000: {"name": "board member", "value": 7},
     5000: {"name": "brand ambassador", "value": 10}
}
    
class IndividualProfileViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows users to be viewed or edited.
    """

    queryset = CompanyProfile.objects.all()
    serializer_class = IndividualProfileSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if user.user_type == "admin":
            return IndividualProfile.objects.all()
        elif user.user_type == "individual":
            if self.request.method == "PATCH":
                return IndividualProfile.objects.filter(user=user)
            if self.request.query_params.get("all") == "true":
                return IndividualProfile.objects.filter(sponsor=user)
            return IndividualProfile.objects.filter(sponsor=user, user__status="approved")
        return IndividualProfile.objects.filter(user=user)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop("partial", False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        if getattr(instance, "_prefetched_objects_cache", None):
            instance._prefetched_objects_cache = {}

        return Response(serializer.data)

    def partial_update(self, request, *args, **kwargs):
        kwargs["partial"] = True
        return self.update(request, *args, **kwargs)
    
    @action(detail=False, methods=['get'], permission_classes = [permissions.IsAdminUser])
    def get_registration_requests(self, request):
        pending_users = IndividualProfile.objects.filter(user__status="pending").select_related("user")
        result = []
        for profile in pending_users:
            user_data = {
                "id": profile.user.pk,
                "name": profile.user.name,
                "sponsor": profile.sponsor.name if profile.sponsor else None,
                "email": profile.user.email,
                "date": profile.user.date_joined,
                "profile_picture": str(profile.user.profile_picture) if profile.user.profile_picture != "" else None
            }
            result.append(user_data)
        return Response(result)
    
    @action(detail=False, methods=['get'], permission_classes = [permissions.IsAdminUser])
    def get_registration_history(self, request):
        non_pending_users = IndividualProfile.objects.filter(user__status__in=["approved", "rejected"]).select_related("user")
        result = []
        for profile in non_pending_users:
            user_data = {
                "id": profile.user.pk,
                "name": profile.user.name,
                "sponsor": profile.sponsor.name if profile.sponsor else None,
                "email": profile.user.email,
                "date": profile.user.date_joined,
                "status": profile.user.status,
                "profile_picture": str(profile.user.profile_picture) if profile.user.profile_picture != "" else None
            }
            result.append(user_data)
        return Response(result)
    
    @action(detail=False, methods=['patch'], permission_classes = [permissions.IsAdminUser])
    def update_reg_status(self, request):
        body = json.loads(request.body)
        sponseeProfile = IndividualProfile.objects.get(user__id=body["userId"]) if body["status"] == "approved" else None
        if sponseeProfile and sponseeProfile.sponsor != None:
            # Direct Referral Bonus
            direct_referral_type, _ = EarningsType.objects.get_or_create(
                bonus_name="Direct Referral Bonus"
            )
            sponsor_pofile = IndividualProfile.objects.get(user__id=sponseeProfile.sponsor.pk)
            UserEarnings.objects.create(
                individual_profile=sponsor_pofile,
                earnings_type=direct_referral_type,
                amount=3000,
                description=f"Direct Referral Bonus for {sponseeProfile.user.name}",
            )
            totalDownline = get_sponsees_and_their_sponsees(sponsor_pofile.user)

            # Update user rank based on totalDownline
            if (len(totalDownline) in rank_hash_table.keys()):
                IndividualProfile.objects.filter(pk=sponseeProfile.pk).update(rank=rank_hash_table[len(totalDownline)]["name"])

            # Matching Bonus
            if (len(totalDownline) + 1) % 2 == 0:
                matching_referral_type, _ = EarningsType.objects.get_or_create(
                        bonus_name="Matching Bonus"
                    )
                no_of_matching_earnings_today = UserEarnings.objects.filter(individual_profile=sponsor_pofile, date=datetime.date.today(), earnings_type=matching_referral_type)
                if len(no_of_matching_earnings_today) < 20:
                    UserEarnings.objects.create(
                        individual_profile=sponsor_pofile,
                        earnings_type=matching_referral_type,
                        amount= 3000,
                        description=f"Matching Bonus",
                    )
        
            # Board Breaker bonus
            if len(totalDownline) == 1024:
                board_breaker_type, _ = EarningsType.objects.get_or_create(
                    bonus_name="Board Breaker Bonus"
                )
                UserEarnings.objects.create(
                    individual_profile=sponsor_pofile,
                    earnings_type=board_breaker_type,
                    amount=1000000,
                    description="Board Breaker Bonus",
                )
        
        CustomUser.objects.filter(pk=body["userId"]).update(status=body["status"])
        return Response()

    @action(detail=False, methods=['patch'], permission_classes = [permissions.IsAdminUser])
    def activate_or_suspend_user(self, request):
        body = json.loads(request.body)
        CustomUser.objects.filter(pk=body["userId"]).update(is_active=body["is_active"])
        return Response()
    
    @action(detail=False, methods=['post'], permission_classes = [permissions.IsAdminUser])
    def user_network_data(self, request):
        body = json.loads(request.body)
        user = CustomUser.objects.get(pk=body["userId"])
        if user:
            user_network = IndividualProfile.objects.filter(sponsor=user, user__status="approved").select_related("user")
            res = []
            for profile in user_network:
                res.append({
                    "name": profile.user.name,
                    "profile_picture": str(profile.user.profile_picture) if profile.user.profile_picture != "" else None,
                    "position": profile.position,
                    "email": profile.user.email,
                    "rank": profile.rank
                })
            return Response({   
                "user_network": res,
                "user": {
                    "name": user.name,
                    "profile_picture": str(user.profile_picture) if user.profile_picture != "" else None,
                }
            }, status=status.HTTP_200_OK)
        else:
            return Response(status=status.HTTP_404_NOT_FOUND)

    @action(detail=False, methods=['get'], permission_classes = [permissions.IsAdminUser])
    def get_admin_dashboard_data(self, request):
        all_users = CustomUser.objects.filter(user_type="individual")
        total_users = len(all_users)
        approved_users = all_users.filter(status="approved")
        active_users = approved_users.filter(is_active=True)
        inactive_users = total_users - len(active_users)
        total_payment_received = 30000 * len(approved_users)
        approved_withdrawals = WalletTransaction.objects.filter(transaction_type="withdraw", status="approved").aggregate(total_amount=Sum('amount'))['total_amount']
        pending_withdrawals = WalletTransaction.objects.filter(transaction_type="withdraw", status="pending").aggregate(total_amount=Sum('amount'))['total_amount']
        drb_total = UserEarnings.objects.filter(earnings_type_id=1).aggregate(total_amount=Sum('amount'))['total_amount']
        mb_total = UserEarnings.objects.filter(earnings_type_id=2).aggregate(total_amount=Sum('amount'))['total_amount']
        ss_total = UserEarnings.objects.filter(earnings_type_id=3).aggregate(total_amount=Sum('amount'))['total_amount']
        bb_total = UserEarnings.objects.filter(earnings_type_id=4).aggregate(total_amount=Sum('amount'))['total_amount']
        pae_total = UserEarnings.objects.filter(earnings_type_id=5).aggregate(total_amount=Sum('amount'))['total_amount']
        return Response({
            "total_users": total_users,
            "active_users": len(active_users) ,
            "inactive_users": inactive_users,
            "total_payment_received": total_payment_received,
            "approved_withdrawals": approved_withdrawals,
            "pending_withdrawals": pending_withdrawals,
            "drb_total": drb_total,
            "mb_total": mb_total,
            "ss_total": ss_total,
            "bb_total": bb_total,
            "pae_total": pae_total
        })

    @action(detail=False, methods=['get'], authentication_classes = [], permission_classes= [permissions.AllowAny])
    def stairstep_bonus_cron(self, request):
        bearer_token = request.headers["Authorization"]
        cron_key = settings.CRON_KEY
        if bearer_token != cron_key:
            return Response(status=status.HTTP_401_UNAUTHORIZED)
        all_eligible_users = IndividualProfile.objects.filter(rank__in=["field marshal", "businesss builder", "board member", "brand ambassador"])
        for user_profile in all_eligible_users:
            all_downline = get_sponsees_and_their_sponsees(user_profile.user)
            total = []
            for member_profile in all_downline:
                date_joined = member_profile.user.date_joined
                month_joined = str(date_joined).split("-")[1]
                current_date = datetime.date.today()
                current_month = str(current_date).split("-")[1]
                month_joined_int = int(month_joined)
                current_month_int = int(current_month)
                if current_month_int - month_joined_int == 1:
                    total.append(member_profile)
            if len(total) > 0:
                stairstep_type, _ = EarningsType.objects.get_or_create(
                        bonus_name="Stairstep Bonus"
                    )
                bonuses = rank_hash_table.values()
                for rank in bonuses:
                    if user_profile.rank == rank["name"]:
                        percentage = rank["value"]
                amount = percentage/100 * 30000 * len(total)
                UserEarnings.objects.create(
                        individual_profile=user_profile,
                        earnings_type=stairstep_type,
                        amount=amount,
                        description="Stair Step Bonus",
                    )
        return Response()


class CompanyProfileViewSet(viewsets.ModelViewSet):
    queryset = CompanyProfile.objects.all()
    serializer_class = CompanyProfileSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if user.user_type == "admin":
            return CompanyProfile.objects.filter(user__status="approved")
        return CompanyProfile.objects.filter(user=user)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop("partial", False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        if getattr(instance, "_prefetched_objects_cache", None):
            instance._prefetched_objects_cache = {}

        return Response(serializer.data)

    def partial_update(self, request, *args, **kwargs):
        kwargs["partial"] = True
        return self.update(request, *args, **kwargs)

    @action(detail=False, methods=['get'], permission_classes = [permissions.IsAdminUser])
    def get_registration_requests(self, request):
        pending_users = CompanyProfile.objects.filter(user__status="pending").select_related("user")
        result = []
        for profile in pending_users:
            user_data = {
                "id": profile.user.pk,
                "name": profile.user.name,
                "email": profile.user.email,
                "date": profile.user.date_joined,
                "profile_picture": str(profile.user.profile_picture) if profile.user.profile_picture != "" else None,
                "company_registration_number": profile.company_registration_number
            }
            result.append(user_data)
        return Response(result)
    
    @action(detail=False, methods=['get'], permission_classes = [permissions.IsAdminUser])
    def get_registration_history(self, request):
        non_pending_users = CompanyProfile.objects.filter(user__status__in=["approved", "rejected"]).select_related("user")
        result = []
        for profile in non_pending_users:
            user_data = {
                "id": profile.user.pk,
                "name": profile.user.name,
                "email": profile.user.email,
                "date": profile.user.date_joined,
                "status": profile.user.status,
                "profile_picture": str(profile.user.profile_picture) if profile.user.profile_picture != "" else None,
                "company_registration_number": profile.company_registration_number
            }
            result.append(user_data)
        return Response(result)
    
    @action(detail=False, methods=['patch'], permission_classes = [permissions.IsAdminUser])
    def update_reg_status(self, request):
        body = json.loads(request.body)
        CustomUser.objects.filter(pk=body["userId"]).update(status=body["status"])
        return Response()
    
    @action(detail=False, methods=['post'], permission_classes = [permissions.IsAdminUser])
    def delete(self, request):
        body = json.loads(request.body)
        user = CustomUser.objects.get(id=body["userId"])
        user.delete()
        return Response()



class CustomTokenObtainPairView(TokenObtainPairView):
    """
    Custom TokenObtainPairView
    """

    serializer_class = CustomUserTokenObtainPairSerializer
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
        except:
            return Response(status=status.HTTP_401_UNAUTHORIZED)
        user = serializer.validated_data["user"]
        if user["user_type"] != "admin":
            if user["profile"]["status"] == "pending":
                return Response(status=status.HTTP_403_FORBIDDEN)
            if user["profile"]["status"] != "approved":
                return Response(status=status.HTTP_401_UNAUTHORIZED)
        response = Response(data={
            "access": serializer.validated_data["access"],
            "refresh": serializer.validated_data["refresh"],
            "user": user,
        }, status=status.HTTP_200_OK)
        return response


class UserEarningsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, user_id):
        try:
            profile = IndividualProfile.objects.get(user_id=user_id)
            earnings = UserEarnings.objects.filter(individual_profile=profile)

            # Get the date parameter from the request, default to today
            date_str = request.query_params.get("date")
            date_now = timezone.now().date()
            if date_str == "yesterday":
                start_date = date_now - timedelta(days=1)
                end_date = start_date
            elif date_str == "today" or date_str == None:
                start_date = date_now
                end_date = start_date
            elif date_str == "last_7_days":
                start_date = date_now - timedelta(days=date_now.weekday() + 7)
                end_date = date_now - timedelta(days=date_now.weekday() + 1)
            else:
                start_date = date_now
                end_date = start_date

            # Filter earnings by the selected date
            daily_earnings = earnings.filter(date__range=[start_date, end_date])
            if date_str == "all_time":
                daily_earnings = earnings

            monthly_earnings = {}
            for month in range(1, 13):
                total = (
                    earnings.filter(date__month=month).aggregate(Sum("amount"))[
                        "amount__sum"
                    ]
                    or 0
                )
                monthly_earnings[timezone.now().replace(day=28).replace(month=month).strftime("%b")] = (
                    total
                )

            # Get all EarningsType objects
            earnings_types = EarningsType.objects.all()

            # Create a dictionary to store daily earnings for each type
            daily_earnings_by_type = {}
            for earnings_type in earnings_types:
                amount = (
                    daily_earnings.filter(earnings_type=earnings_type).aggregate(
                        Sum("amount")
                    )["amount__sum"]
                    or 0
                )
                daily_earnings_by_type[earnings_type.bonus_name] = amount

            data = {
                **daily_earnings_by_type,
                "monthly_earnings": monthly_earnings,
                "total_earnings": sum(earning.amount for earning in earnings),
                "selected_date_earnings": daily_earnings.aggregate(Sum("amount"))[
                    "amount__sum"
                ]
                or 0,
            }

            return Response(data)

        except IndividualProfile.DoesNotExist:
            return Response(
                {"error": "User not found"}, status=status.HTTP_404_NOT_FOUND
            )

class AllEarningsViewSet(viewsets.ModelViewSet):
    queryset = UserEarnings.objects.all()
    serializer_class = UserEarningsSerializer
    permission_classes = [permissions.IsAuthenticated]

    @action(detail=False, methods=['get'], permission_classes = [permissions.IsAuthenticated])
    def get_all_earnings(self, request):
        user = request.user
        user_earnings = UserEarnings.objects.filter(individual_profile__user__pk=user.pk).values()
        return Response({
            "user_earnings": user_earnings
        })

class PasswordResetRequestView(APIView):
    def post(self, request, *args, **kwargs):
        email = request.data.get("email")
        if not email:
            return Response(
                {"detail": "Email is required."}, status=status.HTTP_400_BAD_REQUEST
            )

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response(
                {"detail": "No user found with this email address."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        current_site = get_current_site(request)
        mail_subject = "Reset your password"
        message = render_to_string(
            "useraccounts/password_reset_email.html",
            {
                "user": user,
                "domain": current_site.domain,
                "uid": urlsafe_base64_encode(force_str(user.pk)),
                "token": default_token_generator.make_token(user),
            },
        )
        email = EmailMessage(mail_subject, message, to=[email])
        email.send()

        return Response(
            {"detail": "Password reset email sent."}, status=status.HTTP_200_OK
        )


class PasswordResetView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = PasswordResetSerializer(data=request.data)
        if serializer.is_valid():
            uidb64 = kwargs.get("uidb64")
            token = kwargs.get("token")
            new_password = serializer.validated_data.get("new_password")

            try:
                uid = force_str(urlsafe_base64_decode(uidb64))
                user = User.objects.get(pk=uid)
            except (TypeError, ValueError, OverflowError, User.DoesNotExist):
                user = None

            if user is not None and default_token_generator.check_token(user, token):
                user.set_password(new_password)
                user.save()
                return Response(
                    {"detail": "Password has been reset."}, status=status.HTTP_200_OK
                )
            else:
                return Response(
                    {"detail": "Invalid token."}, status=status.HTTP_400_BAD_REQUEST
                )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class PasswordUpdateView(TokenObtainPairView):
    serializer_class = CustomUserTokenObtainPairSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
        except:
            return Response(status=status.HTTP_401_UNAUTHORIZED)
        new_password = request.data.get("newPassword")
        if not new_password:
            return Response({"message": "newPassword required"},status=status.HTTP_403_FORBIDDEN)
        userDict = serializer.validated_data["user"]
        userObject = CustomUser.objects.get(pk=userDict.get("user_id"))
        userObject.set_password(new_password)
        return Response()

class EarningTypesViewSet(viewsets.ModelViewSet):

    queryset = EarningsType.objects.all()
    serializer_class = EarningsTypeSerializer
    permission_classes = [IsAuthenticated]
