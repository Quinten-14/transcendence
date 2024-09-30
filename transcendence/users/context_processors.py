from django.contrib.auth.decorators import login_required
from users.models import UserProfile

def add_user_profile(request):
    if request.user.is_authenticated:
        user_profile, _ = UserProfile.objects.get_or_create(user=request.user)
        return {'user_profile': user_profile}
    return {}