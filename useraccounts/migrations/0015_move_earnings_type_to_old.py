from django.db import migrations
from django.db import models


def move_earnings_type_to_old(apps, schema_editor):
    UserEarnings = apps.get_model("useraccounts", "UserEarnings")
    UserEarnings.objects.all().update(old_earnings_type=models.F("earnings_type"))


class Migration(migrations.Migration):

    dependencies = [
        ("useraccounts", "0014_userearnings_old_earnings_type"),
    ]

    operations = [
        migrations.RunPython(move_earnings_type_to_old),
    ]
