from django.contrib import admin
from .models import UserProfile
from .models import Match
from .models import PlayerGameStats

# Register your models here.
admin.site.register(UserProfile)
admin.site.register(Match)
admin.site.register(PlayerGameStats)