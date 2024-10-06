from django import template
import datetime


register = template.Library()

@register.filter
def multiply(value, arg):
    try:
        return value * arg
    except Exception as e:
        return 0  # or handle the error as you see fit
    
@register.filter
def divide(value, arg):
    try:
        return value / arg
    except Exception as e:
        return 0
    
@register.filter
def subtract(value, arg):
    try:
        return value - arg
    except Exception as e:
        return 0
    
@register.filter
def add(value, arg):
    try:
        return value + arg
    except Exception as e:
        return 0

@register.filter
def is_power_of_two(value):
    # Check if the value is a power of 2
    if value > 0 and (value & (value - 1)) == 0:
        return 1
    else:
        return 0

@register.filter(name='timedelta_to_duration')
def timedelta_to_duration(value):
    if isinstance(value, datetime.timedelta):
        # Extract total seconds from timedelta
        total_seconds = int(value.total_seconds())
        # Calculate minutes and seconds
        minutes = total_seconds // 60
        seconds = total_seconds % 60
        # Format and return the duration string
        return f"{minutes}:{seconds:02d}"
    else:
        return "Invalid duration"