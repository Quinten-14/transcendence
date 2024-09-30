from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.contrib.auth.models import User
from django.utils import timezone
from django.core.mail import send_mail
from .models import UserProfile
from .models import Match
from django.db import IntegrityError
import pyotp
from datetime import timedelta
from twilio.rest import Client
from django.contrib.auth.hashers import check_password
from .utils import generate_jwt, decode_jwt
import time
from django.conf import settings
import requests
from django.core.files.temp import NamedTemporaryFile
from django.core.files.base import ContentFile
from django.views.decorators.http import require_http_methods
from django.core.exceptions import ObjectDoesNotExist

from django.http import HttpResponse
from requests.auth import HTTPBasicAuth
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.forms import SetPasswordForm
import jwt
import re

def login_user(request):
    if request.user.is_authenticated:
        messages.error(request, 'You are already logged in.')
        return redirect('home')
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        pattern = re.compile(r'^[a-zA-Z0-9@\-_]+$')

        if not pattern.match(username) or not pattern.match(password):
            messages.error(request, 'No special characters allowed except @, -, _.')
            return redirect('login')

        user = authenticate(request, username=username, password=password)
        if user is not None:
            user_profile = UserProfile.objects.get(user=user)
            if not user_profile._two_factor_secret:
                user_profile._two_factor_secret = pyotp.random_base32()
                user_profile.save()
            if user_profile.two_factor_method != 'none':
                request.session['user_id_for_2fa'] = user.id
                if user_profile.two_factor_method in ['email', 'phone']:
                    totp = pyotp.TOTP(user_profile._two_factor_secret)
                    otp_code = totp.now()
                    user_profile.one_time_pass_time = timezone.now()
                    user_profile.save()
                    if user_profile.two_factor_method == 'email':
                        send_email(user.email, otp_code)
                    elif user_profile.two_factor_method == 'phone':
                        send_sms(user_profile.phone_number, otp_code)
                return redirect('2fa')
            login(request, user)
            request.session['language'] = user_profile.language
            payload = {
                'user_id': user.id,
                'exp': time.time() + 3600,
                'iat': time.time()
            }
            token = generate_jwt(payload, settings.SECRET_KEY)
            response = redirect('home')
            response['Authorization'] = token
            return response
        else:
            messages.error(request, 'Invalid username or password.')
            return redirect('login')
    else:   
        return render(request, 'authentication/login.html', {})

def signup_user(request):
    return render(request, 'authentication/signup.html', {})
    
def logout_user(request):
    logout(request)
    return redirect('home')

def signup_user(request):
    pattern = re.compile(r'^[a-zA-Z0-9@\-_]+$')
    if request.user.is_authenticated:
        messages.error(request, 'You are already logged in.')
        return redirect('home')
    if request.method == 'POST':
        first_name = request.POST['firstName']
        last_name = request.POST['lastName']
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']
        password2 = request.POST['password2']

        if not all([first_name, last_name, username, email, password, password2]):
            messages.error(request, 'All fields are required.')
            return redirect('signup')

        if password != password2:
            messages.error(request, 'Passwords do not match.')
            return redirect('signup')

        if User.objects.filter(username=username).exists():
            messages.error(request, 'That username is already taken.')
            return redirect('signup')

        if not (pattern.match(first_name) and pattern.match(last_name) and pattern.match(username) and pattern.match(password) and pattern.match(password2)):
            messages.error(request, 'No special characters allowed except @, -, _.')
            return redirect('signup')

        try:
            user = User.objects.create_user(username, email, password)

            user.first_name = first_name
            user.last_name = last_name
            user.save()
    
            messages.success(request, 'Account created successfully.')

        except Exception as e:
            messages.error(request, f'Error creating account: {e}')
            return redirect('signup')

        user_profile, created = UserProfile.objects.get_or_create(user=user)
        user_profile._two_factor_secret = pyotp.random_base32()
        user_profile.save()
        login(request, user)
        request.session['language'] = user_profile.language
        payload = {
            'user_id': user.id,
            'exp': time.time() + 3600,
            'iat': time.time()
        }
        token = generate_jwt(payload, settings.SECRET_KEY)
        response = redirect('home')
        response['Authorization'] = token
        return response
    else:
        return render(request, 'authentication/signup.html', {})


def two_factor_auth(request):
    if request.user.is_authenticated:
        messages.error(request, 'You are already logged in.')
        return redirect('home')
    
    if request.method == 'POST':
        user_id = request.session.get('user_id_for_2fa')
        if not user_id:
            return redirect('login')
        
        code_digits = [request.POST.get(f'code{i}') for i in range(1, 7)]
        user_code = ''.join(code_digits)
        user = User.objects.get(id=user_id)
        user_profile = UserProfile.objects.get(user=user)

        totp = pyotp.TOTP(user_profile._two_factor_secret)
        if user_profile.two_factor_method in ['email', 'phone']:
            if totp.verify(user_code, valid_window=900):
                login(request, user)
                request.session['language'] = user_profile.language
                del request.session['user_id_for_2fa']
                payload = {
                    'user_id': user.id,
                    'exp': time.time() + 3600,
                    'iat': time.time()
                }
                token = generate_jwt(payload, settings.SECRET_KEY)
                response = redirect('home')
                response['Authorization'] = token
                return response
            messages.error(request, 'Invalid or expired 2FA code. Please try again.')
        elif user_profile.two_factor_method == 'app':
            if totp.verify(user_code):
                login(request, user)
                request.session['language'] = user_profile.language
                del request.session['user_id_for_2fa']
                payload = {
                    'user_id': user.id,
                    'exp': time.time() + 3600,
                    'iat': time.time()
                }
                token = generate_jwt(payload, settings.SECRET_KEY)
                response = redirect('home')
                response['Authorization'] = token
                return response
            messages.error(request, 'Invalid 2FA code. Please try again.')
        return redirect('login')
    else:
        return render(request, 'authentication/two_factor_auth.html')
    

def send_email(email, otp_code):
    send_mail("2FA Authentication Code", "Your verification code is: " + otp_code + ". You have 15 minutes before this code expires.", "19transcendence@gmail.com", [email], fail_silently=False,)

def send_sms(phone_number, otp_code):
    account_sid = "AC883c6c6a8d3f15956b311a6d8b1ba453"
    auth_token = "d35fa18962416c5d4c12f94d1b103500"
    client = Client(account_sid, auth_token)
    message = client.messages.create(body="Your verification code is: "+otp_code+ ". You have 15 minutes before this code expires.", from_="+12568297604", to="+32494061143")

def delete_user(request):
    if request.method == 'POST':
        password = request.POST.get('password')
        user = request.user
        if check_password(password, user.password):
            user.delete()
            return redirect('home')
        else:
            messages.error(request, 'Invalid password. Account not deleted.')
            return redirect('home')
    return redirect('home')

import json
from django.http import JsonResponse
from django.shortcuts import render
from requests_oauthlib import OAuth2Session          
from oauthlib.oauth2 import BackendApplicationClient 
import os

def auth(request):
    return redirect('https://api.intra.42.fr/oauth/authorize?client_id=u-s4t2ud-1755c29da13e81b993917226b83117dbc4aefef65d09f6376410b0738f23ed3a&redirect_uri=https%3A%2F%2Flocalhost%3A8443%2Fusers%2Fauth_callback&response_type=code')

def loginIntra(request):
    auth_code = request.GET.get('code')
    if not auth_code:
        return auth(request)
    return HttpResponse("Already had auth_code")


def unique_username(intra_username, max_attempts=5):
    original_username = intra_username
    i = 0
    if not User.objects.filter(username=intra_username).exists():
        return intra_username
    user = User.objects.get(username=intra_username)
    while i < max_attempts and user.password:
        intra_username = original_username + str(i + 1)
        i += 1
        if not User.objects.filter(username=intra_username).exists():
            return intra_username
        user = User.objects.get(username=intra_username)

    if i == max_attempts:
        return None
    return intra_username


def auth_callback(request):
    UID = os.getenv('UID')
    SECRET = os.getenv('SECRET')

    auth_code = request.GET.get('code')

    if not auth_code:
        return HttpResponse("did not have auth_code")

    oauth = OAuth2Session(client_id=UID, redirect_uri='https://localhost:8443/users/auth_callback')

    token_url = 'https://api.intra.42.fr/oauth/token'
    try:
        token_response = oauth.fetch_token(token_url=token_url,
                                           code=auth_code,
                                           client_id=UID,
                                           client_secret=SECRET)
    except Exception as e:
        return HttpResponse(f"Error: didnt get access token, status code {str(e)}.", status=500)

    access_token = token_response.get('access_token')
    user_info_response = requests.get(
            'https://api.intra.42.fr/v2/me',
            headers={'Authorization': f'Bearer {access_token}'}
            )
    user_info = user_info_response.json()
    intra_username = user_info['login']
    profilePictureLink = user_info['image']['versions']['large']

    intra_username = unique_username(intra_username)

    if intra_username is None:
        messages.error(request, 'That username is already taken.')
        return redirect('signup')

    # Create the user if they don't exist
    user, created = User.objects.get_or_create(username=intra_username)

    if created:
        user.first_name = user_info['first_name']
        user.last_name = user_info['last_name']
        user.email = user_info['email']
        user.save()

    # Retrieve or create user profile
    profile, profile_created = UserProfile.objects.get_or_create(user=user)

    # If profile was created for the first time, set the two-factor secret and profile picture
    if profile._two_factor_secret is None:
        profile._two_factor_secret = pyotp.random_base32()

    # Fetch and save the profile picture, even if the profile already existed
    response = requests.get(profilePictureLink)
    if response.status_code == 200:
        img_temp = NamedTemporaryFile(delete=True)
        img_temp.write(response.content)
        img_temp.flush()
        img_temp.seek(0)

        # Save the profile picture
        profile.profilePicture.save(f"{intra_username}_profile.jpg", ContentFile(img_temp.read()), save=True)
        img_temp.close()

    # Save the profile to ensure changes (secret and picture) are persisted
    profile.save()

    # Log the user in and redirect to home
    login(request, user)
    return redirect('home')




def player2auth(request):
    username = request.POST.get('username')
    password = request.POST.get('password')


    pattern = re.compile(r'^[a-zA-Z0-9@\-_]+$')

    try:
        if password is not None:
            if not pattern.match(username) or not pattern.match(password):
                return JsonResponse({'status': 'error', 'message': 'No special characters allowed except @, -, _.'})
            user = authenticate(request, username=username, password=password)
            if user is not None:
                return JsonResponse({'status': True})
            else:
                return JsonResponse({'status': 'authentication_failed'})
        else:
            if not pattern.match(username):
                return JsonResponse({'status': 'error', 'message': 'No special characters allowed except @, -, _.'})
            user = User.objects.get(username=username)
            user_profile = UserProfile.objects.get(user=user)
            totp = pyotp.TOTP(user_profile._two_factor_secret)
            otp_code = totp.now()
            send_email_2auth(user.email, otp_code)
            return JsonResponse({'status': 'otp_sent'})
    except ObjectDoesNotExist:
        return JsonResponse({'status': 'user_not_found'})

    return JsonResponse({'status': 'error'})

def confirmOtp(request):
    code = request.POST.get('code')
    username = request.POST.get('username')


    pattern = re.compile(r'^[a-zA-Z0-9@\-_]+$')

    if not code or not username:
        return JsonResponse({'status': 'error', 'message': 'Missing code or username'})

    if not pattern.match(username) or not pattern.match(code):
        return JsonResponse({'status': 'error', 'message': 'No special characters allowed except @, -, _.'})
    
    try:
        user = User.objects.get(username=username)
        user_profile = UserProfile.objects.get(user=user)
        totp = pyotp.TOTP(user_profile._two_factor_secret)
        
        if totp.verify(code, valid_window=900):  # OTP valid for 15 minutes
            # Set an OTP verified flag in the session
            request.session['otp_verified'] = True
            request.session['otp_verified_user'] = user.id  # Track which user has been OTP verified
            return JsonResponse({'status': 'verified'})
        else:
            return JsonResponse({'status': 'error', 'message': 'OTP verification failed'})
    
    except User.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': 'User does not exist'})
    except UserProfile.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': 'UserProfile does not exist'})
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)})


def send_email_2auth(email, otp_code):
    send_mail("Game Verification Code", "Your verification code is: " + otp_code + ". You have 15 minutes before this code expires.", "19transcendence@gmail.com", [email], fail_silently=False,)

from django.urls import reverse
from django.db import DatabaseError
from django.utils.dateparse import parse_duration
import json
from django.core.exceptions import ValidationError

def submit_game_data(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid request method'}, status=400)
    
    try:
        data = json.loads(request.body)
        print("Received data:", data)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    
    try:
        player1_name = data['players'][0]
        player2_name = data['players'][1]

        player1 = User.objects.get(username=player1_name)
        player2 = User.objects.get(username=player2_name) if player2_name != 'AI' else None
    except User.DoesNotExist:
        return JsonResponse({'error': 'Invalid player names'}, status=400)
    
    try:
        end_time = data['endTime']
        if not isinstance(end_time, int):
            return JsonResponse({'error': 'Invalid endTime format'}, status=400)
        
        duration = timedelta(seconds=end_time)
    except (ValueError, TypeError):
        return JsonResponse({'error': 'Invalid duration format'}, status=400)
    
    try:
        final_score = data['finalScore']
        player1_score = final_score.get('player1', 0)
        player2_score = final_score.get('player2', 0)
    except KeyError:
        return JsonResponse({'error': 'Invalid finalScore format'}, status=400)
    
    try:
        points = data.get('points', [])
        longest_rally = max((point.get('rally', 0) for point in points), default=0)
    except KeyError:
        return JsonResponse({'error': 'Invalid points format'}, status=400)

    try:
        game_type = data['typeGame']
        if game_type not in ['Tournament']:
            game_type = 'Pickup'
    except KeyError:
        return JsonResponse({'error': 'Invalid gameType format'}, status=400)
    
    try:
        match = Match(
            player1=player1,
            player2=player2,
            is_player2_ai=(player2 is None),
            duration=duration,
            player1_score=player1_score,
            player2_score=player2_score,
            longest_rally=longest_rally,
            raw_data=data,
            typeGame=game_type
        )
        match.save()
    except (ValidationError, IntegrityError) as e:
        return JsonResponse({'error': str(e)}, status=400)
    except DatabaseError:
        return JsonResponse({'error': 'Database error'}, status=500)
    
    redirect_url = reverse('home')
    return JsonResponse({'redirect': redirect_url})

def fillResetPassEmail(request):
    if request.user.is_authenticated:
        messages.error(request, 'You are already logged in.')
        return redirect('home')
    
    if request.method == 'POST':
        email = request.POST.get('resetEmail')

        pattern = re.compile(r'^[a-zA-Z0-9@\-_]+$')
        
        if email:
            if not pattern.match(email):
                messages.error(request, 'No special characters allowed except @, -, _.')
                return redirect('fillResetPassEmail')
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                messages.error(request, 'No user with that email address was found.')
                return redirect('fillResetPassEmail')

            reset_link = 'http://localhost:8000/users/reset_password?token=' + generate_jwt({'user_id': user.id}, settings.SECRET_KEY)
            send_mail('Password Reset', f'Click the following link to reset your password: {reset_link}', '19transcendence@gmail.com', [email], fail_silently=False)
            messages.success(request, 'An email has been sent with instructions to reset your password.')
            return redirect('login')
        else:
            messages.error(request, 'Please enter an email address.')
            return redirect('fillResetPassEmail')
    return render(request, 'authentication/resetFormEmail.html', {})

def reset_password(request):
    token = request.GET.get('token', None)
    if not token:
        messages.error(request, 'No reset token provided.')
        return redirect('login')
    
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        messages.error(request, 'Reset token has expired.')
        return redirect('fillResetPassEmail')
    except jwt.InvalidTokenError:
        messages.error(request, 'Invalid reset token.')
        return redirect('fillResetPassEmail')
    
    user_id = payload.get('user_id')
    try:
        user = User.objects.get(pk=user_id)
    except User.DoesNotExist:
        messages.error(request, 'User does not exist.')
        return redirect('fillResetPassEmail')
    
    if request.method == 'POST':
        form = SetPasswordForm(user, request.POST)
        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)
            messages.success(request, 'Your password has been set successfully!')
            return redirect('login')
        else:
            messages.error(request, 'Please correct the error below.')
    else:
        form = SetPasswordForm(user)
    
    return render(request, 'authentication/resetPassword.html', {'form': form})