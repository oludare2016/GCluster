# Generated by Django 5.0.8 on 2024-10-23 08:57

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("referrals", "0006_sharerequest"),
    ]

    operations = [
        migrations.AddField(
            model_name="product",
            name="product_link_type",
            field=models.CharField(
                choices=[
                    ("whatsapp", "Whatsapp"),
                    ("website", "Website"),
                    ("phone", "Phone"),
                ],
                default="website",
                max_length=20,
            ),
        ),
    ]
