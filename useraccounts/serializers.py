from django.contrib.auth.hashers import make_password
from rest_framework import serializers
from .models import (
    CustomUser,
    IndividualProfile,
    CompanyProfile,
    UserEarnings,
    EarningsType,
)
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer


class CustomUserSerializer(serializers.ModelSerializer):
    """
    Serializer for CustomUser
    """

    class Meta:
        model = CustomUser
        fields = ["email", "password", "name", "user_type", "profile_picture"]
        extra_kwargs = {"password": {"write_only": True}}


class IndividualProfileSerializer(serializers.ModelSerializer):
    """
    Serializer for IndividualProfile
    """

    class Meta:
        model = IndividualProfile
        fields = [
            "email",
            "name",
            "phone_number",
            "address",
            "country",
            "profile_picture",
            "date_joined",
            "status",
            "user_type",
            "user_id",
            "gender",
            "sponsor",
            "rank",
            "membership_type",
            "total_earnings",
            "state",
            "city",
            "password",
            "position",
            "is_active",
            "bank_code",
            "account_name",
            "account_number",
            "payment_method"
        ]

    email = serializers.EmailField(source="user.email")
    name = serializers.CharField(source="user.name")
    phone_number = serializers.CharField(
        source="user.phone_number", required=False, allow_blank=True
    )
    address = serializers.CharField(
        source="user.address", required=False, allow_blank=True
    )
    country = serializers.CharField(
        source="user.country", required=False, allow_blank=True
    )
    profile_picture = serializers.ImageField(
        source="user.profile_picture", required=False
    )
    date_joined = serializers.DateField(source="user.date_joined", read_only=True)
    status = serializers.CharField(source="user.status", read_only=True)
    user_type = serializers.CharField(source="user.user_type", read_only=True)
    user_id = serializers.IntegerField(source="user.id", read_only=True)
    gender = serializers.CharField(required=False, allow_blank=True)
    sponsor = serializers.PrimaryKeyRelatedField(
        queryset=IndividualProfile.objects.all(), required=False
    )
    rank = serializers.CharField(required=False, allow_blank=True)
    membership_type = serializers.CharField(required=False, allow_blank=True)
    state = serializers.CharField(source="user.state", required=False, allow_blank=True)
    total_earnings = serializers.FloatField(required=False, read_only=False)
    city = serializers.CharField(source="user.city", required=False, allow_blank=True)
    password = serializers.CharField(source="user.password", write_only=True)
    position = serializers.CharField(required=True)
    is_active = serializers.CharField(source="user.is_active", required=False)

    def validate_password(self, value):
        return make_password(value)

    def create(self, validated_data):
        user = CustomUser.objects.create_user(**validated_data)
        IndividualProfile.objects.create(user=user, **validated_data)
        return user

    def update(self, instance, validated_data):
        user_data = validated_data.pop("user", {})
        user = instance.user

        for attr, value in user_data.items():
            if value is not None:  # Only update if a value is provided
                setattr(user, attr, value)
        user.save()

        for attr, value in validated_data.items():
            if value is not None:  # Only update if a value is provided
                setattr(instance, attr, value)
        instance.save()

        return instance


class CompanyProfileSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(source="user.email")
    name = serializers.CharField(source="user.name")
    phone_number = serializers.CharField(
        source="user.phone_number", required=False, allow_blank=True
    )
    address = serializers.CharField(
        source="user.address", required=False, allow_blank=True
    )
    country = serializers.CharField(
        source="user.country", required=False, allow_blank=True
    )
    profile_picture = serializers.ImageField(
        source="user.profile_picture", required=False
    )
    status = serializers.CharField(source="user.status", read_only=True)
    user_type = serializers.CharField(source="user.user_type", read_only=True)
    user_id = serializers.IntegerField(source="user.id", read_only=True)
    company_registration_number = serializers.CharField(
        required=False, allow_blank=True
    )
    state = serializers.CharField(source="user.state", required=False, allow_blank=True)
    city = serializers.CharField(source="user.city", required=False, allow_blank=True)
    password = serializers.CharField(source="user.password", write_only=True)
    is_active = serializers.CharField(source="user.is_active", required=False)
    # company_id = serializers.CharField(source="user.is_active", required=False)

    def validate_password(self, value):
        return make_password(value)

    class Meta:
        model = CompanyProfile
        fields = [
            "email",
            "name",
            "phone_number",
            "address",
            "country",
            "profile_picture",
            "status",
            "user_type",
            "user_id",
            "company_registration_number",
            "state",
            "city",
            "password",
            "is_active"
        ]

    def create(self, validated_data):
        user = CustomUser.objects.create_user(**validated_data)
        IndividualProfile.objects.create(user=user, **validated_data)
        return user

    def update(self, instance, validated_data):
        user_data = validated_data.pop("user", {})
        user = instance.user

        for attr, value in user_data.items():
            if value is not None:  # Only update if a value is provided
                setattr(user, attr, value)
        user.save()

        for attr, value in validated_data.items():
            if value is not None:  # Only update if a value is provided
                setattr(instance, attr, value)
        instance.save()

        return instance


class SignupSerializer(serializers.Serializer):
    """
    Serializer for user signup.
    """

    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    name = serializers.CharField()
    user_type = serializers.ChoiceField(choices=["individual", "company"])
    phone_number = serializers.CharField(required=False)
    address = serializers.CharField(required=False)
    country = serializers.CharField(required=False)
    profile_picture = serializers.ImageField(required=False)
    # Fields for individual
    gender = serializers.ChoiceField(choices=["male", "female"], required=False)
    sponsor_id = serializers.IntegerField(required=False)
    position = serializers.ChoiceField(choices=["left", "right"], required=True)
    # Field for company
    company_registration_number = serializers.CharField(required=False)

    def create(self, validated_data):
        user_fields = [
            "email",
            "password",
            "user_type",
            "name",
            "phone_number",
            "address",
            "country",
            "profile_picture",
        ]
        user_data = {
            field: validated_data.pop(field)
            for field in user_fields
            if field in validated_data
        }

        user = CustomUser.objects.create_user(**user_data)
        sponsor_id = validated_data.pop("sponsor_id", None)

        if user.user_type == "individual":
            IndividualProfile.objects.create(
                user=user, sponsor_id=sponsor_id, **validated_data
            )
        elif user.user_type == "company":
            CompanyProfile.objects.create(user=user, **validated_data)

        return user

    def validate(self, data):
        user_type = data.get("user_type")

        if user_type == "individual":
            required_fields = ["gender"]
        elif user_type == "company":
            required_fields = ["company_registration_number"]
        else:
            raise serializers.ValidationError("Invalid user type")

        for field in required_fields:
            if not data.get(field):
                raise serializers.ValidationError(
                    f"{field} is required for {user_type} signup"
                )

        return data


class CustomUserTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    Serializer for CustomUserTokenObtainPair
    """

    def validate(self, attrs):
        """
        Validate and return the user and access token pair.
        :param attrs:
        :return:
        """
        data = super().validate(attrs)

        user = self.user
        if user.user_type == "individual":
            profile_data = IndividualProfileSerializer(
                IndividualProfile.objects.get(user=user)
            ).data
        elif user.user_type == "company":
            profile_data = CompanyProfileSerializer(
                CompanyProfile.objects.get(user=user)
            ).data
        else:
            profile_data = {}

        data.update(
            {
                "refresh": data.get("refresh"),
                "access": data.get("access"),
                "user": {
                    "user_id": user.id,
                    "email": user.email,
                    "is_active": user.is_active,
                    "user_type": user.user_type,
                    "profile": {**profile_data, "user_id": user.id},
                },
            }
        )

        return data


class UserEarningsSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserEarnings
        fields = ["amount", "description", "date", "earnings_type"]


class PasswordResetSerializer(serializers.Serializer):
    uidb64 = serializers.CharField()
    new_password = serializers.CharField(min_length=6)

    def validate_new_password(self, value):
        if len(value) < 6:
            raise serializers.ValidationError(
                "Password must be at least 6 characters long."
            )
        return value


class EarningsTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = EarningsType
        fields = "__all__"
