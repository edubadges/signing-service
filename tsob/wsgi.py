import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tsob.settings.development')  # dev
# os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'tsob.settings.production') # prod

application = get_wsgi_application()
