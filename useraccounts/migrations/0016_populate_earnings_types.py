from django.db import migrations


def populate_earnings_types(apps, schema_editor):
    EarningsType = apps.get_model("useraccounts", "EarningsType")
    UserEarnings = apps.get_model("useraccounts", "UserEarnings")

    earnings_choices = [
        ("direct_referral_bonus", "Direct Referral Bonus"),
        ("matching_bonus", "Matching Bonus"),
        ("stairstep_bonus", "Stairstep Bonus"),
        ("board_breaker_bonus", "Board Breaker Bonus"),
        ("promote_and_earn_bonus", "Promote and Earn Bonus"),
    ]

    # Create EarningsType instances
    earnings_type_map = {}
    for choice, name in earnings_choices:
        earnings_type = EarningsType.objects.create(bonus_name=name)
        earnings_type_map[choice] = earnings_type

    # Update UserEarnings records
    for old_type, new_type in earnings_type_map.items():
        UserEarnings.objects.filter(old_earnings_type=old_type).update(
            earnings_type=new_type
        )


class Migration(migrations.Migration):

    dependencies = [
        ("useraccounts", "0015_move_earnings_type_to_old"),
    ]

    operations = [
        migrations.RunPython(populate_earnings_types),
    ]
