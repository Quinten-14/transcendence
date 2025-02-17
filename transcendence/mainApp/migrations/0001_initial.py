# Generated by Django 5.1 on 2024-09-03 23:23

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Tournament',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100)),
                ('max_time', models.IntegerField()),
                ('max_score', models.IntegerField()),
            ],
        ),
        migrations.CreateModel(
            name='TournamentParticipant',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('still_in', models.BooleanField(default=True)),
                ('endPosition', models.IntegerField(default=0)),
                ('tournament', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='mainApp.tournament')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
