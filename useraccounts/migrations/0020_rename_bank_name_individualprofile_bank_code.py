# Generated by Django 5.0.8 on 2024-10-24 11:40

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("useraccounts", "0019_individualprofile_account_name_and_more"),
    ]

    operations = [
        migrations.RenameField(
            model_name="individualprofile",
            old_name="bank_name",
            new_name="bank_code",
        ),
    ]
