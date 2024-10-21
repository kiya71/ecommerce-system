# Generated by Django 5.0.7 on 2024-10-17 07:27

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0004_rename_profile_picture_userprofile_userprofile'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='userprofile',
            name='userprofile',
        ),
        migrations.AddField(
            model_name='userprofile',
            name='profile_picture',
            field=models.ImageField(blank=True, upload_to='userprofile'),
        ),
    ]
