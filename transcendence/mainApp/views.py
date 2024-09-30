from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth.models import User
from users.models import UserProfile
from users.models import Match
from users.models import PlayerGameStats
from .forms import ProfilePictureForm
from .forms import ProfileBannerForm
from django.http import HttpResponseRedirect
from django.urls import reverse
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.utils import timezone
from django.contrib.auth import authenticate
import pyotp
from django.db.models import Q, Count, F, Case, When, IntegerField, Value as V
from django.db.models.functions import Coalesce
from datetime import timedelta
from django.utils.timesince import timesince
import random
from django.http import JsonResponse
from .models import Tournament, TournamentParticipant
from django.views.decorators.http import require_POST

def home(request):
    context = {}
    
    if request.user.is_authenticated:
        user_profile, created = UserProfile.objects.get_or_create(user=request.user)

        # If profile was created for the first time, set the two-factor secret and profile picture
        if user_profile._two_factor_secret is None:
            user_profile._two_factor_secret = pyotp.random_base32()
            user_profile.save()

        game_stats, createdStats = PlayerGameStats.objects.get_or_create(userProfile=request.user.userprofile)

        if createdStats:
            game_stats.save()
            context = {
            'user_profile': user_profile,
            'game_stats': game_stats
            }
        else:
            context = {
            }
    return render(request, 'index.html', context)

def leaderboard(request):
    leaderboard_by_wins = PlayerGameStats.objects.all().order_by('-gamesWon')
    leaderboard_by_win_streak = PlayerGameStats.objects.all().order_by('-highestWinStreak')

    context = {
        'leaderboard_by_wins': leaderboard_by_wins,
        'leaderboard_by_win_streak': leaderboard_by_win_streak,
    }

    return render(request, 'leaderboard.html', context)

@login_required
def hostTournament(request):
    participant_ids = request.session.get('tournament_players', [])

    if request.user.id not in participant_ids:
        participant_ids.append(request.user.id)
        request.session['tournament_players'] = participant_ids
        request.session.modified = True

    tournament_players = User.objects.filter(id__in=participant_ids)

    return render(request, 'hostTournament.html', {
        'tournament_players': tournament_players
    })

@login_required
def clear_tournament_participants(request):
    if 'tournament_players' in request.session:
        del request.session['tournament_players']
        request.session.modified = True
    
    return JsonResponse({'success': True})

@login_required
def addParticipant(request):
    if request.method == 'POST':
        participantUsername = request.POST.get('username')
        participantPassword = request.POST.get('password', None)  # Password is optional

        # Check if the user is OTP-verified in this session
        otp_verified_user_id = request.session.get('otp_verified_user', None)
        otp_verified = request.session.get('otp_verified', False)

        if participantPassword:
            # Authenticate using password
            participant = authenticate(username=participantUsername, password=participantPassword)
        elif otp_verified and otp_verified_user_id:
            try:
                # Check if the OTP-verified user is the one trying to log in
                participant = User.objects.get(username=participantUsername, id=otp_verified_user_id)
            except User.DoesNotExist:
                return JsonResponse({'error': 'User does not exist or cannot be authenticated.'})
        else:
            return JsonResponse({'error': 'Wrong password.'})

        if participant:
            participant_ids = request.session.get('tournament_players', [])
            
            if participant == request.user:
                return JsonResponse({'error': 'You cannot add yourself as a participant.'})
            
            if participant.id not in participant_ids:
                participant_ids.append(participant.id)
                request.session['tournament_players'] = participant_ids
                request.session.modified = True

                if request.session.get('otp_verified'):
                    del request.session['otp_verified']
                    del request.session['otp_verified_user']
                return JsonResponse({'success': True})
            else:
                return JsonResponse({'error': 'User is already a participant.'})
        else:
            return JsonResponse({'error': 'Invalid username or password. Please try again.'})
    
    return JsonResponse({'error': 'Invalid request method.'}, status=405)



@login_required
def startTournament(request):
    if request.method == 'POST':
        tournament_name = request.POST.get('tournamentName')
        max_time = request.POST.get('maxTime')
        max_score = request.POST.get('maxScore')

        
        if max_time is None or max_score is None:
            return JsonResponse({'error': 'Missing max_time or max_score.'}, status=400)

        try:
            max_time = int(max_time)
            max_score = int(max_score)
            if not (1 <= max_time <= 5) or not (3 <= max_score <= 15):
                raise ValueError("Invalid input values.")
        except ValueError as e:
            return JsonResponse({'error': str(e)}, status=400)
        
        participant_ids = request.session.get('tournament_players', [])
        if len(participant_ids) < 2:
            messages.error(request, 'A tournament must have at least 4 participants.')
            return redirect('hostTournament')
        
        tournament = Tournament(name=tournament_name, max_time=max_time, max_score=max_score)
        tournament.save()

        for participant_id in participant_ids:
            user = User.objects.get(id=participant_id)
            TournamentParticipant.objects.create(user=user, tournament=tournament)
            user_profile = UserProfile.objects.get(user=user)
            player_game_stats = user_profile.playergamestats
            player_game_stats.tournamentsPlayed += 1
            player_game_stats.save()

        del request.session['tournament_players']
        request.session.modified = True
        return JsonResponse({'success': True, 'tournament_id': tournament.id})
    return JsonResponse({'success':False})

import json
@login_required
def generateTournamentBracket(request, tournament_id):
    tournament = Tournament.objects.get(id=tournament_id)
    session_key = f'tournament_{tournament_id}_bracket'

    if session_key in request.session:
        bracket = request.session[session_key]
    else:
        participants = list(TournamentParticipant.objects.filter(tournament=tournament).values_list('user__username', flat=True))
        if len(participants) % 2 != 0:
            participants.append('AI')
        random.shuffle(participants)
        
        bracket = {f'match{i//2 + 1:02}': {'players': (participants[i], participants[i+1]), 'playing': True, 'round': 1} for i in range(0, len(participants), 2)}
        
        request.session[session_key] = bracket
        request.session.modified = True

    return render(request, 'tournamentBracket.html', {'tournament': tournament, 'bracket': bracket, 'bracket_json': json.dumps(bracket, indent=2)})

@login_required
def playTournamentMatch(request, tournament_id, match_number):
    tournament = Tournament.objects.get(id=tournament_id)
    session_key = f'tournament_{tournament_id}_bracket'
    bracket = request.session.get(session_key)

    if not bracket:
        return redirect('tournament_bracket', tournament_id=tournament_id)

    match = bracket.get(f'match{match_number:02}')
    if not match:
        return redirect('tournament_bracket', tournament_id=tournament_id)

    player1 = User.objects.get(username=match[0])
    player2 = User.objects.get(username=match[1])

    return render(request, 'playTournamentMatch.html', {
        'tournament': tournament,
        'match_number': match_number,
        'player1': player1,
        'player2': player2,
    })

@csrf_exempt
@require_POST
def updatePlayingStatus(request, tournament_id, match_id):
    tournament = Tournament.objects.get(id=tournament_id)
    session_key = f'tournament_{tournament_id}_bracket'

    if session_key in request.session:
        bracket = request.session[session_key]
        if match_id in bracket:
            bracket[match_id]['playing'] = False
            winner = request.headers.get('Winner')
            lowest_bracket_id = None
            total_brackets = 0
            total_brackets_round = 0
            current_round = bracket[match_id].get('round', 1)
            match_number = int(match_id[5:]) - 1

            for key in bracket:
                total_brackets += 1
                if bracket[key].get('round', 1) == current_round:
                    total_brackets_round += 1
                    if lowest_bracket_id is None or int(key[5:]) < lowest_bracket_id:
                        lowest_bracket_id = int(key[5:]) - 1
                if bracket[key].get('round', 1) > current_round:
                    total_brackets -= 1
                    break

            if total_brackets_round == 0:
                return JsonResponse({'status': 'error', 'message': 'No matches in the current round'}, status=400)
            
            next_bracket_number = int(int(int(match_number - lowest_bracket_id) / 2) % (total_brackets_round / 2) + total_brackets) + 1
            next_bracket = f'match{next_bracket_number:02}'
            if next_bracket not in bracket:
                bracket[next_bracket] = {'players': [winner, ''], 'playing': False, 'round': current_round + 1}
            elif bracket[next_bracket]['players'][1] == '':
                bracket[next_bracket]['players'][1] = winner
                bracket[next_bracket]['playing'] = True
             
            request.session[session_key] = bracket
            request.session.modified = True

            # loop through all the match ids in the bracket and check if playing is True. If all are False, the tournament is over
            if all(not bracket[key]['playing'] for key in bracket):
                user = User.objects.get(username=winner)
                user_profile = UserProfile.objects.get(user=user)
                player_game_stats = user_profile.playergamestats
                player_game_stats.tournamentsWon += 1
                player_game_stats.save()
                tournament.winner = user

                tournament.save()

            return JsonResponse({'status': 'success'})
    return JsonResponse({'status': 'error'}, status=400)


def lastGamePage(request):
    if (request.user.is_authenticated):
        matches = Match.objects.all().order_by('-date')
        return render(request, 'lastGames.html', {'matches': matches})
    else:
        messages.error(request, 'You must be logged in to access this page.')
        return redirect('home')

def dashboard(request):
    if request.user.is_authenticated:
        game_stats, created = PlayerGameStats.objects.get_or_create(userProfile=request.user.userprofile)

        if created:
            game_stats.save()

        last_10_games = Match.objects.filter(
            Q(player1=request.user) | Q(player2=request.user)
        ).order_by('-date')[:10]
        last_10_games = last_10_games[::-1]

        labels = [game.date.strftime("%Y-%m-%d") for game in last_10_games]
        data = []
        for game in last_10_games:
            if game.player1 == request.user:
                data.append(game.player1_score)
            else:
                data.append(game.player2_score)

        most_wins_against = (
            Match.objects.filter(winner=str(request.user.id))
            .annotate(
                opponent=Case(
                    When(player1=request.user, then=F('player2')),
                    When(player2=request.user, then=F('player1')),
                    output_field=IntegerField()
                )
            )
            .exclude(opponent=request.user.id)
            .values('opponent')
            .annotate(wins=Count('id'))
            .order_by('-wins')[:3]
        )

        most_wins_against_profiles = []
        for win in most_wins_against:
            opponent_user = User.objects.get(id=win['opponent'])
            opponent_profile = UserProfile.objects.get(user=opponent_user)
            most_wins_against_profiles.append({
                'username': opponent_user.username,
                'profile': opponent_profile,
                'wins': win['wins'],
            })

        mostWinsLeaderboardSpot = PlayerGameStats.objects.filter(gamesWon__gt=game_stats.gamesWon).count() + 1
        highestWinStreakLeaderboardSpot = PlayerGameStats.objects.filter(highestWinStreak__gt=game_stats.highestWinStreak).count() + 1

        context = {
            'game_stats': game_stats,
            'labels': labels,
            'data': data,
            'most_wins_against': most_wins_against_profiles,
            'mostWinsLeaderboardSpot': mostWinsLeaderboardSpot,
            'highestWinStreakLeaderboardSpot': highestWinStreakLeaderboardSpot,
        }

        return render(request, 'dashboard.html', context)
    else:
        messages.error(request, 'You must be logged in to access this page.')
        return redirect('home')

def gameOverview(request, match_id):
    match = Match.objects.get(id=match_id)
    player1_goals = 0
    player2_goals = 0

    longest_goal_streak = 0
    current_streak = 0
    last_goal_time = None
    longest_time_between_goals = timedelta(seconds=0)

    leaderboard = PlayerGameStats.objects.all().order_by('-gamesWon')
    leaderboard_usernames = [stats.userProfile.user.username for stats in leaderboard]

    player1_position = leaderboard_usernames.index(match.player1.username) + 1 if match.player1.username in leaderboard_usernames else "No wins yet"

    if match.player2 is None:
        player2_position = "AI"
    else:
        player2_position = leaderboard_usernames.index(match.player2.username) + 1 if match.player2.username in leaderboard_usernames else "No wins yet"

    timeline = []
    messages = []
    titles = []

    player1 = match.player1
    player2 = match.player2

    for point in match.raw_data['points']:
        scorer_is_player1 = point['scorer'] == (player1.username if player1 else 'AI')
        if scorer_is_player1:
            player1_goals += 1
        else:
            player2_goals += 1
        
        if current_streak == 0 or scorer_is_player1 == (timeline[-1]['scorer'] == (player1.username if player1 else 'AI')):
            current_streak += 1
        else:
            current_streak = 1

        if current_streak > longest_goal_streak:
            longest_goal_streak = current_streak

        current_goal_time = timedelta(seconds=point['time'])
        if last_goal_time is not None:
            time_between_goals = current_goal_time - last_goal_time
            if time_between_goals > longest_time_between_goals:
                longest_time_between_goals = time_between_goals
        
        last_goal_time = current_goal_time
        
        timeline.append({
            'scorer': point['scorer'],
            'rally': point['rally'],
            'time': point['time'],
            'player1_goals': player1_goals,
            'player2_goals': player2_goals,
            'is_player1': scorer_is_player1,
        })

    minutes, seconds = divmod(longest_time_between_goals.total_seconds(), 60)
    formatted_time_between_goals = f"{int(minutes):01}:{int(seconds):02}"

    match_duration_seconds = match.duration.total_seconds()

    if longest_goal_streak >= 5:
        titles.append("Onstuitbare Reeks")
        messages.append(f"{('AI' if not player1 or player1_goals <= player2_goals else player1.username)} ging op een onstuitbare reeks, scoorde {longest_goal_streak} opeenvolgende doelpunten!")

    if longest_time_between_goals.total_seconds() > 120:
        titles.append("Defensieve Meesterklas")
        messages.append(f"{('AI' if not player1 or player1_goals <= player2_goals else player1.username)} hield de tegenstander {formatted_time_between_goals} lang van scoren af zonder een doelpunt tegen te krijgen!")

    if any(point['time'] >= match_duration_seconds - 60 for point in match.raw_data['points']):
        titles.append("Beslissende Prestatie")
        messages.append(f"{('AI' if not player1 or player1_goals <= player2_goals else player1.username)} leverde op het beslissende moment, scoorde het winnende doelpunt met minder dan 60 seconden op de klok!")

    if player1_goals > player2_goals:
        titles.append(f"Dominantie van {('Speler 1' if not player1 else player1.username)}")
        messages.append(f"{('Speler 1' if not player1 else player1.username)} presteerde beter dan 'AI', won met {player1_goals - player2_goals} doelpunten!")

    if player2_goals > player1_goals:
        titles.append("AI Dominantie")
        messages.append(f"'AI' presteerde beter dan {('Speler 1' if not player1 else player1.username)}, won met {player2_goals - player1_goals} doelpunten!")

    if player1_goals == player2_goals:
        titles.append("Gelijkspel")
        messages.append("Het was een nagelbijtend gelijkspel! Beide spelers scoorden evenveel.")

    if longest_goal_streak >= 3 and longest_goal_streak < 5:
        titles.append("Sterke Reeks")
        messages.append(f"{('AI' if not player1 or player1_goals <= player2_goals else player1.username)} had een sterke reeks met {longest_goal_streak} opeenvolgende doelpunten!")

    if longest_goal_streak < 3:
        titles.append("Korte Reeks")
        messages.append(f"De wedstrijd had meerdere korte reeksen, met de langste zijnde {longest_goal_streak} doelpunten.")

    if not messages:
        titles.append("Wedstrijdoverzicht")
        messages.append("Het was een spannende wedstrijd met schitterende momenten van beide spelers!")

    if messages:
        index = random.randint(0, len(messages) - 1)
        message_to_display = messages[index]
        title_to_display = titles[index]
    else:
        message_to_display = "Geen speciale hoogtepunten in deze wedstrijd."
        title_to_display = "Wedstrijdoverzicht"

    context = {
        'match': match,
        'timeline': timeline,
        'longest_goal_streak': longest_goal_streak,
        'longest_time_between_goals': formatted_time_between_goals,
        'message': message_to_display,
        'message_title': title_to_display,
        'player1_position': player1_position,
        'player2_position': player2_position,
    }
    
    return render(request, 'gameOverview.html', context)

def userProfile(request, username):
    profile_user = get_object_or_404(User, username=username)
    user_profile = profile_user.userprofile

    if not PlayerGameStats.objects.filter(userProfile=user_profile).exists():
        PlayerGameStats.objects.create(userProfile=user_profile)

    last_games = Match.objects.filter(
        Q(player1=profile_user) | Q(player2=profile_user)
    ).order_by('-date')
    return render(request, 'user_profile.html', {'user': request.user, 'profile_user': profile_user, 'user_profile': user_profile, 'last_games': last_games, 'gameStats': PlayerGameStats.objects.get(userProfile=user_profile)})

@login_required
def updateProfilePicture(request):
    if request.method == 'POST':
        form = ProfilePictureForm(request.POST, request.FILES, instance=request.user.userprofile)
        file = request.FILES.get('profilePicture')
        if file:
            if not file.content_type in ['image/jpeg', 'image/png', 'image/gif']:
                messages.error(request, 'Invalid file type. Please upload an image file.')
                return HttpResponseRedirect(request.META.get('HTTP_REFERER', '/'))
        if form.is_valid():
            form.save()
            return JsonResponse({'status': 'success'})
    return JsonResponse({'status': 'error'}, status=405)

@login_required
def updateBannerPicture(request):
    if request.method == 'POST':
        form = ProfileBannerForm(request.POST, request.FILES, instance=request.user.userprofile)
        file = request.FILES.get('bannerPicture')
        if file:
            if not file.content_type in ['image/jpeg', 'image/png', 'image/gif']:
                messages.error(request, 'Invalid file type. Please upload an image file.')
                return HttpResponseRedirect(request.META.get('HTTP_REFERER', '/'))
        if form.is_valid():
            form.save()
            return JsonResponse({'status': 'success'})
    return JsonResponse({'status': 'error'}, status=405)

@login_required
def updateUsername(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        if username:
            if User.objects.filter(username=username).exists():
                messages.error(request, 'This username already exists. Please choose a different one.')
                return HttpResponseRedirect(request.META.get('HTTP_REFERER', '/'))
            else:
                request.user.username = username
                request.user.save()
                messages.success(request, 'Je gebruikersnaam is geupdate.')
                return JsonResponse({'status': 'success'})
    return JsonResponse({'status': 'error'}, status=405)

@login_required
def updateNumber(request):
    if request.method == 'POST':
        phone_number = request.POST.get('phone_number')
        if phone_number:
            request.user.userprofile.phone_number = phone_number
            request.user.userprofile.save()
            messages.success(request, 'Je telefoonnummer is geupdate.')
            return JsonResponse({'status': 'success'})
    return JsonResponse({'status': 'error'}, status=405)

@login_required
def updateLanguage(request):
    if request.method == 'POST':
        language = request.POST.get('language')
        if language:
            request.user.userprofile.language = language
            request.user.userprofile.save()
            return JsonResponse({'status': 'success'})
    return JsonResponse({'status': 'error'}, status=405)

@csrf_exempt
def update_user_status(request):
    if request.user.is_authenticated:
        profile = request.user.userprofile
        profile.last_online = timezone.now()
        profile.save()
        return JsonResponse({'status': 'success'})
    return JsonResponse({'status': 'error'}, status=403)

def search_user(request):
    if 'term' in request.GET:
        qs = User.objects.filter(username__icontains=request.GET.get('term'))
        users = list(qs.values('username'))
        return JsonResponse(users, safe=False)
    return JsonResponse([], safe=False)

def add_friend(request):
    if request.method == 'POST':
        user = request.user
        friend = get_object_or_404(User, username=request.POST.get('username'))
        user.userprofile.friends.add(friend.userprofile)
        user.userprofile.friendRequests.remove(friend.userprofile)
        return redirect('/user/' + friend.username)
    return redirect('home')

def remove_friend(request):
    if request.method == 'POST':
        user = request.user
        friend = get_object_or_404(User, username=request.POST.get('username'))
        user.userprofile.friends.remove(friend.userprofile)
        return redirect('/user/' + friend.username)
    return redirect('home')

def block_user(request):
    if request.method == 'POST':
        user = request.user
        blocked_user = get_object_or_404(User, username=request.POST.get('username'))

        user.userprofile.friends.remove(blocked_user.userprofile)
        user.userprofile.blockedUsers.add(blocked_user.userprofile)

        return redirect('/user/' + blocked_user.username)
    return redirect('home')

def unblock_user(request):
    if request.method == 'POST':
        user = request.user
        blocked_user = get_object_or_404(User, username=request.POST.get('username'))
        user.userprofile.blockedUsers.remove(blocked_user.userprofile)
        return redirect('/user/' + blocked_user.username)
    return redirect('home')

@login_required
def send_friend_request(request):
    if request.method == 'POST':
        recipient_username = request.POST.get('username')
        recipient_user = get_object_or_404(User, username=recipient_username)
        
        recipient_user.userprofile.friendRequests.add(request.user.userprofile)
        
        return redirect('/user/' + recipient_username)
    return redirect('home')

def decline_friend_request(request):
    if request.method == 'POST':
        user = request.user
        friend = get_object_or_404(User, username=request.POST.get('username'))
        user.userprofile.friendRequests.remove(friend.userprofile)
        return redirect('/user/' + friend.username)
    return redirect('home')

def enable_email_2fa(request):
    if request.method == 'POST':
        user = request.user
        user.userprofile.two_factor_method = 'email'
        user.userprofile.save()
        return redirect('home')
    return redirect('home')

def enable_phone_2fa(request):
    if request.method == 'POST':
        user = request.user
        if not user.userprofile.phone_number:
            messages.error(request, 'Please add your phone number to your profile settings to enable phone 2FA.')
            return redirect('home')
        user.userprofile.two_factor_method = 'phone'
        user.userprofile.save()
        return redirect('home')
    return redirect('home')

def enable_app_2fa(request):
    if request.method == 'POST':
        two_factor_code = request.POST.get('2faCode')
        user = request.user
        totp = pyotp.TOTP(user.userprofile._two_factor_secret)
        if totp.verify(two_factor_code):
            user.userprofile.two_factor_method = 'app'
            user.userprofile.save()
            return redirect('home')
        else:
            messages.error(request, 'Invalid 2FA code. Please try again.')
            return redirect('home')

def disable_2fa(request):
    if request.method == 'POST':
        user = request.user
        user.userprofile.two_factor_method = 'none'
        user.userprofile.save()
        return redirect('home')
    return redirect('home')