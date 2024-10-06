from django import forms
from users.models import UserProfile

class ProfilePictureForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        fields = ['profilePicture']

class ProfileBannerForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        fields = ['bannerPicture']