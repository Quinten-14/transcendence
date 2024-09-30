import os
import json
from django.core.wsgi import get_wsgi_application

# Generate googlekey.json
private_key_id = os.getenv('GOOGLE_PRIVATE_KEY_ID')
private_key = os.getenv('GOOGLE_PRIVATE_KEY').replace('\\n', '\n')
google_key = {
    "type": "service_account",
    "project_id": "swift-implement-434213-g6",
    "private_key_id": private_key_id,
    "private_key": private_key,
    "client_email": "ft-transcendence@swift-implement-434213-g6.iam.gserviceaccount.com",
    "client_id": "115962133800953314030",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/ft-transcendence%40swift-implement-434213-g6.iam.gserviceaccount.com",
    "universe_domain": "googleapis.com"
}

with open('/app/mainApp/googlekey.json', 'w') as f:
    json.dump(google_key, f, indent=4)

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'transcendence.settings')

application = get_wsgi_application()