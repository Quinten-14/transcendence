from django import template
from ..utils import translate_text

register = template.Library()

@register.filter
def translate(text, args):
    user = args.user
    if user.is_authenticated:
        if user.userprofile:
            if user.userprofile.language:
                return translate_text(text, user.userprofile.language)
    return text