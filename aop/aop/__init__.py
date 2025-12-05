"""
AOP Django Application

Loads Celery app on Django startup.
"""

# Load Celery app
from .celery import app as celery_app

__all__ = ('celery_app',)
