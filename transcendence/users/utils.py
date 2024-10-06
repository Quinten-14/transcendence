from cryptography.fernet import Fernet
from django.conf import settings
import base64
import hashlib
import random
import hmac
import json
import time

def derive_key(secret_key):
    key = hashlib.sha256(secret_key.encode()).digest()
    encoded_key = base64.urlsafe_b64encode(key)
    if len(encoded_key) == 44:
        return encoded_key
    else:
        fallback_key = base64.urlsafe_b64encode(settings.FALLBACK_KEY.encode())
        return fallback_key

fernet = Fernet(derive_key(settings.SECRET_KEY))

def encrypt_message(message: str) -> str:
    
    return fernet.encrypt(message.encode()).decode()

def decrypt_message(message: str) -> str:
    if message is not None:
        return fernet.decrypt(message.encode()).decode()

def one_time_pass():
    string = ""
    for i in range(6):
        string += random.choice("1234567890")
    return string

def base64_url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

def base64_url_decode(data):
    padding = '=' * (4 - (len(data) % 4))
    return base64.urlsafe_b64decode(data + padding)

def generate_jwt(payload, secret):
    header = {"alg": "HS256", "typ": "JWT"}
    header_encoded = base64_url_encode(json.dumps(header).encode('utf-8'))
    payload_encoded = base64_url_encode(json.dumps(payload).encode('utf-8'))
    signature = hmac.new(secret.encode('utf-8'), f'{header_encoded}.{payload_encoded}'.encode('utf-8'), hashlib.sha256).digest()
    signature_encoded = base64_url_encode(signature)
    return f'{header_encoded}.{payload_encoded}.{signature_encoded}'

def decode_jwt(token, secret):
    try:
        header_encoded, payload_encoded, signature_encoded = token.split('.')
        signature = base64_url_decode(signature_encoded)
        expected_signature = hmac.new(secret.encode('utf-8'), f'{header_encoded}.{payload_encoded}'.encode('utf-8'), hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected_signature):
            return None
        payload = json.loads(base64_url_decode(payload_encoded))
        if payload.get('exp') < time.time():
            return None
        return payload
    except Exception as e:
        return None

