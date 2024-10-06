from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('', views.home, name='home'),
    path('updateProfilePicture/', views.updateProfilePicture, name='updateProfilePicture'),
    path('updateBannerPicture/', views.updateBannerPicture, name='updateBannerPicture'),
    path('updateUsername/', views.updateUsername, name='updateUsername'),
    path('updateNumber/', views.updateNumber, name='updateNumber'),
    path('updateLanguage/', views.updateLanguage, name='updateLanguage'),
    path('user/<str:username>/', views.userProfile, name='userProfile'),
    path('update_status/', views.update_user_status, name='update_status'),
    path('search_user/', views.search_user, name='search_user'),
    path('add_friend/', views.add_friend, name='add_friend'),
    path('remove_friend/', views.remove_friend, name='remove_friend'),
    path('block_user/', views.block_user, name='block_user'),
    path('unblock_user/', views.unblock_user, name='unblock_user'),
    path('send_friend_request/', views.send_friend_request, name='send_friend_request'),
    path('decline_friend_request/', views.decline_friend_request, name='decline_friend_request'),
    path('enable_email_2fa/', views.enable_email_2fa, name='enable_email_2fa'),
    path('enable_phone_2fa/', views.enable_phone_2fa, name='enable_phone_2fa'),
    path('enable_app_2fa/', views.enable_app_2fa, name='enable_app_2fa'),
    path('disable_2fa/', views.disable_2fa, name='disable_2fa'),
    path('lastGames/', views.lastGamePage, name='lastGames'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('gameOverview/<int:match_id>/', views.gameOverview, name='gameOverview'),
    path('leaderboard/', views.leaderboard, name='leaderboard'),
    path('hostTournament/', views.hostTournament, name='hostTournament'),
    path('addParticipant/', views.addParticipant, name='addParticipant'),
    path('clear-tournament-participants/', views.clear_tournament_participants, name='clear_tournament_participants'),
    path('startTournament/', views.startTournament, name='startTournament'),
    path('tournament/<int:tournament_id>/bracket/', views.generateTournamentBracket, name='tournament_bracket'),
    path('tournament/<int:tournament_id>/update_playing_status/<str:match_id>/', views.updatePlayingStatus, name='update_playing_status'),
]