# Create a new migration file
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("useraccounts", "0013_alter_userearnings_earnings_type"),
    ]

    operations = [
        migrations.AddField(
            model_name="userearnings",
            name="old_earnings_type",
            field=models.CharField(max_length=55, null=True),
        ),
    ]
