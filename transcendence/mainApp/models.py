from django.db import models
from django.contrib.auth.models import User

class Tournament(models.Model):
    name = models.CharField(max_length=100)
    max_time = models.IntegerField()
    max_score = models.IntegerField()

    def __str__(self):
        return self.name
    
class TournamentParticipant(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    tournament = models.ForeignKey(Tournament, on_delete=models.CASCADE)
    still_in = models.BooleanField(default=True)
    endPosition = models.IntegerField(default=0)