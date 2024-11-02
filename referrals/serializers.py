from rest_framework import serializers
from .models import Product, SupportTicket, UserRanking, Staff, TicketReply
from useraccounts.models import CustomUser
from useraccounts.serializers import CustomUserSerializer
from uuid import UUID


class ProductSerializer(serializers.ModelSerializer):
    """
    Serializer for the Product model.
    """

    company_name = serializers.SerializerMethodField()

    class Meta:
        model = Product
        fields = "__all__"
        read_only_fields = ("company",)

    def get_company_name(self, obj):
        """
        Get the company name from the related CustomUser model.
        """
        return obj.company.name if obj.company else None

    def validate(self, data):
        """
        Validates the data provided in the request.
        """
        request = self.context.get("request")
        if request and hasattr(request, "user"):
            user = request.user
            if user.user_type not in ["company", "admin"]:
                raise serializers.ValidationError(
                    "Only companies or admins can create or edit products."
                )
            if self.instance is None:
                data["company"] = user
        return data


class SupportTicketReplySerializer(serializers.ModelSerializer):
    """
    Serializer for the SupportTicketReply model.
    """

    ticket = serializers.UUIDField()
    replied_by = CustomUserSerializer(many=False, read_only=True)

    class Meta:
        model = TicketReply
        fields = "__all__"
        read_only_fields = ("replied_by", "date_created")

    def validate_ticket(self, value):
        """
        Validates the ticket provided in the request.
        :param value:
        :return:
        """
        try:
            uuid_value = UUID(str(value))
            ticket = SupportTicket.objects.get(uuid=uuid_value)
            return ticket
        except (ValueError, SupportTicket.DoesNotExist):
            raise serializers.ValidationError("Invalid ticket UUID.")

    def create(self, validated_data):
        # Ensure the ticket is set correctly
        validated_data["ticket"] = validated_data["ticket"]
        return super().create(validated_data)


class SupportTicketSerializer(serializers.ModelSerializer):
    """
    Serializer for the SupportTicket model.
    """

    replies = SupportTicketReplySerializer(many=True, read_only=True)
    submitted_by = CustomUserSerializer(many=False, read_only=True)

    class Meta:
        """
        Meta class for the SupportTicket model.
        """

        model = SupportTicket
        fields = "__all__"
        read_only_fields = ("submitted_by",)

    def validate(self, data):
        """
        Validates the data provided in the request.
        """
        request = self.context.get("request")
        if request and hasattr(request, "user"):
            user = request.user
            if request.method == "PATCH" and user.user_type == "admin":
                return data
            if user.user_type not in ["individual", "company"]:
                raise serializers.ValidationError(
                    "Only individuals or companies can create support tickets."
                )
            data["submitted_by"] = user
        return data

    def create(self, validated_data):
        """
        Create and return a new `SupportTicket` instance, given the validated data.
        """
        return super().create(validated_data)


class UserRankingSerializer(serializers.ModelSerializer):
    """
    Serializer for the UserRanking model.
    """

    class Meta:
        """
        Meta class for the UserRankingSerializer.
        """

        model = UserRanking
        fields = "__all__"


class VerifyAccountSerializer(serializers.Serializer):
    """
    Serializer for verifying an account.
    """

    account_number = serializers.CharField(max_length=20)
    bank_code = serializers.CharField(max_length=10)
    account_name = serializers.CharField(max_length=255, read_only=True)
    first_name = serializers.CharField(max_length=255, read_only=True)
    last_name = serializers.CharField(max_length=255, read_only=True)
    other_name = serializers.CharField(max_length=255, read_only=True)
    bank_name = serializers.CharField(max_length=255, read_only=True)


class StaffSerializer(serializers.ModelSerializer):
    """
    Serializer for the Staff model.
    """

    email = serializers.EmailField(source="user.email", read_only=True)
    name = serializers.CharField(source="user.name")
    phone_number = serializers.CharField(source="user.phone_number")
    role = serializers.CharField()
    is_active = serializers.CharField(source="user.is_active", required=False)

    class Meta:
        model = Staff
        fields = [
            "id",
            "email",
            "name",
            "phone_number",
            "role",
            "is_active",
            "user_id"
        ]
        read_only_fields = ["id"]

    def create(self, validated_data):
        """
        Create a new staff member with the provided validated data.
        """
        user_data = validated_data.pop("user")
        email = self.context["request"].data.get("email")
        password = self.context["request"].data.get(
            "password"
        )  # Get password from request data

        user = CustomUser.objects.create_user(
            email=email, password=password, user_type="admin"
        )

        staff = Staff.objects.create(user=user, **validated_data)

        if staff.role == "superadmin":
            user.is_superuser = True
            user.is_staff = True
        elif staff.role == "admin":
            user.is_staff = True
        user.save()

        return staff

    def update(self, instance, validated_data):
        """
        Update the user data of an instance and save the changes.
        """
        user_data = validated_data.pop("user", {})
        for attr, value in user_data.items():
            setattr(instance.user, attr, value)
        instance.user.save()

        return super().update(instance, validated_data)
