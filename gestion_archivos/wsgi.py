"""
WSGI config for gestion_archivos project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.0/howto/deployment/wsgi/
"""

import os
import sys 
from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'gestion_archivos.settings')

application = get_wsgi_application()

path = '/home/carlosvillarino/gestionarchivos'
if path not in sys.path:
    sys.path.append(path)

os.environ['DJANGO_SETTINGS_MODULE'] = 'gestionarchivos.settings'

from django.core.wsgi import get_wsgi_application
application = get_wsgi_application()