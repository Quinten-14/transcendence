from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils import timezone
from datetime import timedelta
from django.db.models import Q, Count
from django.utils.timezone import now

class UserProfile(models.Model):
    TWOFA_CHOICES = [
        ('email', 'Email'),
        ('phone', 'Phone'),
        ('app', 'App'),
        ('none', 'None')
    ]
    LANGUAGE_CHOICES = [
        ('nl', 'Dutch'),
        ('en', 'English'),
        ('es', 'Spanish'),
        ('fr', 'French'),
        ('de', 'German'),
        ('it', 'Italian'),
        ('ja', 'Japanese'),
        ('ko', 'Korean'),
        ('zh', 'Chinese'),
        ('ct', 'Cat'),
    ]
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    is_two_factor_enabled = models.BooleanField(default=False)
    two_factor_method = models.CharField(max_length=5, choices=TWOFA_CHOICES, default='none')
    profilePicture = models.ImageField(upload_to='profile_pictures/', default='defaults/default_profile.png')
    bannerPicture = models.ImageField(upload_to='banner_pictures/', default='defaults/default_banner.png')
    language = models.CharField(max_length=2, choices=LANGUAGE_CHOICES, default='en')
    last_online = models.DateTimeField(auto_now=True)
    _two_factor_secret = models.CharField(max_length=255, blank=True, null=True, db_column='two_factor_secret')
    friends = models.ManyToManyField('self', blank=True, symmetrical=True)
    friendRequests = models.ManyToManyField('self', blank=True, symmetrical=False, related_name='friend_requests')
    blockedUsers = models.ManyToManyField('self', blank=True, symmetrical=False, related_name='blocked_users')
    one_time_pass = models.CharField(max_length=100, blank=True, null=True)
    one_time_pass_time = models.DateTimeField(auto_now=True)
    phone_number = models.CharField(max_length=15, blank=True, null=True)

    @property
    def is_user_online(self):
        return self.last_online >= timezone.now() - timedelta(minutes=1)

    def generate_2fa_secret(self):
        import pyotp
        self._two_factor_secret = pyotp.random_base32()
        self.save()

    def get_2fa_secret(self):
        return self._two_factor_secret

    def get_qr_url(self):
        import urllib.parse
        secret = self.get_2fa_secret()
        username = urllib.parse.quote(self.user.username)
        return f'otpauth://totp/{username}?secret={secret}&issuer=ft_transcendence'

@receiver(post_save, sender=User)
def create_or_update_user_profile(sender, instance, created, **kwargs):
    if created:
        user_profile = UserProfile.objects.create(user=instance)
    else:
        user_profile = instance.userprofile

    user_profile.save()

class PlayerGameStats(models.Model):
    userProfile = models.OneToOneField(UserProfile, on_delete=models.CASCADE)
    gamesPlayed = models.IntegerField(default=0)
    gamesWon = models.IntegerField(default=0)
    gamesLost = models.IntegerField(default=0) 
    gamesDraw = models.IntegerField(default=0)
    highestWinStreak = models.IntegerField(default=0)
    currentWinStreak = models.IntegerField(default=0)
    tournamentsWon = models.IntegerField(default=0)
    tournamentsSecond = models.IntegerField(default=0)
    tournamentsThird = models.IntegerField(default=0)
    tournamentsPlayed = models.IntegerField(default=0)

    def update_stats(self):
        matches = Match.objects.filter(Q(player1=self.userProfile.user) | Q(player2=self.userProfile.user))
        self.gamesPlayed = matches.count()
        self.gamesWon = matches.filter(winner=str(self.userProfile.user.id)).count()
        self.gamesLost = matches.exclude(winner=str(self.userProfile.user.id)).exclude(winner='Draw').count()
        self.gamesDraw = matches.filter(winner='Draw').count()
        
        current_streak = 0
        highest_streak = self.highestWinStreak

        for match in matches:
            if match.winner == str(self.userProfile.user.id):
                current_streak += 1
                if current_streak > highest_streak:
                    highest_streak = current_streak
            else:
                current_streak = 0

        self.currentWinStreak = current_streak
        self.highestWinStreak = highest_streak

        self.save()
    
class Match(models.Model):
    GameTypes = [
        ('Pickup', 'Pickup Game'),
        ('Tournament', 'Tournament Game'),
    ]
    player1 = models.ForeignKey(User, on_delete=models.CASCADE, related_name='matches_as_player1')
    player2 = models.ForeignKey(User, on_delete=models.CASCADE, related_name='matches_as_player2', null=True, blank=True)
    is_player2_ai = models.BooleanField(default=False)
    winner = models.CharField(max_length=100, blank=True, null=True)
    date = models.DateTimeField(auto_now_add=True)
    duration = models.DurationField()
    player1_score = models.IntegerField()
    player2_score = models.IntegerField()
    longest_rally = models.IntegerField()
    typeGame = models.CharField(max_length=10, choices=GameTypes, default='Pickup')
    raw_data = models.JSONField(default=dict)

    def save(self, *args, **kwargs):
        if self.player1_score > self.player2_score:
            self.winner = str(self.player1_id)
        elif self.player2_score > self.player1_score:
            if self.is_player2_ai:
                self.winner = 'AI'
            else:
                self.winner = str(self.player2_id)
        else:
            self.winner = 'Draw'
        super().save(*args, **kwargs)

    @property
    def match_history_for_player1(self):
        return Match.objects.filter(player1=self.player1)
    
    @property
    def match_history_for_player2(self):
        return Match.objects.filter(player2=self.player2)
    
@receiver(post_save, sender=Match)
def update_player_stats(sender, instance, **kwargs):
    if instance.player1:
        try:
            player1_profile = instance.player1.userprofile
            player1_game_stats, created = PlayerGameStats.objects.get_or_create(userProfile=player1_profile)
            player1_game_stats.update_stats()
        except UserProfile.DoesNotExist:
            pass
    
    if instance.player2 and not instance.is_player2_ai:
        try:
            player2_profile = instance.player2.userprofile
            player2_game_stats, created = PlayerGameStats.objects.get_or_create(userProfile=player2_profile)
            player2_game_stats.update_stats()
        except UserProfile.DoesNotExist:
            pass