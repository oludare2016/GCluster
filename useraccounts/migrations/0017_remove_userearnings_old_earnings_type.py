from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("useraccounts", "0016_populate_earnings_types"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="userearnings",
            name="old_earnings_type",
        ),
    ]
