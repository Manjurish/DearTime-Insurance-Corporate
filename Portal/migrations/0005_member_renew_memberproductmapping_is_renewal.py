# Generated by Django 4.1.3 on 2023-10-17 09:27

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Portal', '0004_member_read_datetime_member_updated_datetime'),
    ]

    operations = [
        migrations.AddField(
            model_name='member',
            name='renew',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='memberproductmapping',
            name='is_renewal',
            field=models.BooleanField(default=False),
        ),
    ]
