from django.contrib import admin
from .models import Tournament, TournamentParticipant

# Register your models here.
admin.site.register(Tournament)
admin.site.register(TournamentParticipant)