from django.utils.deprecation import MiddlewareMixin
from django.http import JsonResponse, HttpResponseRedirect
from django.urls import reverse
from .utils import decode_jwt
from django.conf import settings
import time

EXCLUDED_PATHS = [
    '/',
]

class JWTAuthenticationMiddleware(MiddlewareMixin):
    def process_request(self, request):
        if any(request.path.startswith(path) for path in EXCLUDED_PATHS):
            return None

        token = request.META.get('HTTP_AUTHORIZATION')
        if token:
            payload = decode_jwt(token, settings.SECRET_KEY)
            if payload:
                if payload['exp'] < time.time():
                    request.session.flush()
                    return HttpResponseRedirect(reverse('login'))
                request.user_id = payload['user_id']
            else:
                return JsonResponse({'error': 'Invalid token'}, status=401)
        else:
            return JsonResponse({'error': 'Token required'}, status=401)