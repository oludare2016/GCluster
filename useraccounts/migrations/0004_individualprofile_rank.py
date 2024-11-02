# Generated by Django 5.0.8 on 2024-08-18 09:21

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("useraccounts", "0003_individualprofile_sponsor"),
    ]

    operations = [
        migrations.AddField(
            model_name="individualprofile",
            name="rank",
            field=models.CharField(
                choices=[
                    ("entrepreneur", "Entrepreneur"),
                    ("field marshall", "Field Marshall"),
                    ("business builder", "Business Builder"),
                    ("board member", "Board Member"),
                    ("brand ambassador", "Brand Ambassador"),
                ],
                default="entrepreneur",
                max_length=20,
            ),
        ),
    ]