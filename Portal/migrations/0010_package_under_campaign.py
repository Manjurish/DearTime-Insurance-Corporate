# Generated by Django 4.1.3 on 2024-10-14 12:14

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Portal', '0009_corporateprofile_corporate_campaign_code_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='package',
            name='under_campaign',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
    ]
