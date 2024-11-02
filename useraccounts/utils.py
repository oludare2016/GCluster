from decimal import Decimal


def calculate_and_create_bonuses(sponsor_user):
    """
    Calculates and creates bonuses for a given sponsor user.
    Args:
        sponsor_user: The user for whom the bonuses are being calculated.
    Returns:
        The total bonus amount, which is the sum of the direct referral bonus and the matching bonus.
    """
    from .models import UserEarnings, IndividualProfile, CustomUser, EarningsType

    sponsor_profile = IndividualProfile.objects.get(user=sponsor_user)

    # Count approved direct referrals
    approved_referrals = CustomUser.objects.filter(
        individual_profile__sponsor=sponsor_user, status="approved"
    ).count()

    # Calculate direct referral bonuses
    direct_referral_bonus = Decimal("30000.00") * approved_referrals

    # Get or create EarningsType for direct referral bonus
    direct_referral_type, _ = EarningsType.objects.get_or_create(
        bonus_name="Direct Referral Bonus"
    )

    # Create or update direct referral bonus entry
    UserEarnings.objects.update_or_create(
        individual_profile=sponsor_profile,
        earnings_type=direct_referral_type,
        defaults={
            "amount": direct_referral_bonus,
            "description": f"Direct Referral Bonus for {approved_referrals} approved referrals",
        },
    )

    # Calculate matching bonus
    matching_bonus_pairs = approved_referrals // 2
    matching_bonus = Decimal("3000.00") * matching_bonus_pairs

    # Get or create EarningsType for matching bonus
    matching_bonus_type, _ = EarningsType.objects.get_or_create(
        bonus_name="Matching Bonus"
    )

    # Create or update matching bonus entry
    UserEarnings.objects.update_or_create(
        individual_profile=sponsor_profile,
        earnings_type=matching_bonus_type,
        defaults={
            "amount": matching_bonus,
            "description": f"Matching Bonus for {matching_bonus_pairs} pairs of approved referrals",
        },
    )

    return direct_referral_bonus + matching_bonus
