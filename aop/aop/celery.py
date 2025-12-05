"""
Celery Configuration for AOP

Configures Celery for async task processing:
- WAL event processing
- Event forwarding
- Periodic maintenance tasks
- Beat schedule for recurring jobs
"""

import os
from celery import Celery
from celery.schedules import crontab
from django.conf import settings

# Set default Django settings
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'aop.settings')

# Create Celery app
app = Celery('aop')

# Load config from Django settings with 'CELERY_' prefix
app.config_from_object('django.conf:settings', namespace='CELERY')

# Auto-discover tasks from all registered Django apps
app.autodiscover_tasks()


# ============================================================================
# Celery Configuration
# ============================================================================

app.conf.update(
    # Broker settings (Redis)
    broker_url=os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/2'),
    result_backend=os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/3'),
    
    # Task settings
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    
    # Task execution
    task_acks_late=True,  # Acknowledge after task completes
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=4,  # Prefetch 4 tasks per worker
    
    # Result expiration
    result_expires=3600,  # Results expire after 1 hour
    
    # Task routing
    task_routes={
        'api.tasks.process_wal_entry': {'queue': 'processing'},
        'api.tasks.forward_to_evaluation_engine': {'queue': 'forwarding'},
        'api.tasks.push_to_websocket': {'queue': 'websocket'},
        'api.tasks.consume_redis_wal': {'queue': 'wal_consumer'},
        'api.tasks.consume_db_wal': {'queue': 'wal_consumer'},
        'api.tasks.generate_trace_record': {'queue': 'finalization'},
        'api.tasks.capture_environment_snapshot': {'queue': 'finalization'},
        'api.tasks.evaluate_run': {'queue': 'evaluation'},
        'api.retention_tasks.cleanup_expired_data': {'queue': 'maintenance'},
        'api.retention_tasks.redact_pii_pipeline': {'queue': 'privacy'},
        'api.retention_tasks.process_consent_expirations': {'queue': 'privacy'},
        'api.retention_tasks.execute_deletion_request': {'queue': 'privacy'},
        'api.retention_tasks.redact_run_pii': {'queue': 'privacy'},
    },
    
    # Task time limits
    task_time_limit=300,  # 5 minutes hard limit
    task_soft_time_limit=240,  # 4 minutes soft limit
    
    # Worker settings
    worker_max_tasks_per_child=1000,  # Restart worker after 1000 tasks
    worker_disable_rate_limits=False,
)


# ============================================================================
# Celery Beat Schedule (Periodic Tasks)
# ============================================================================

app.conf.beat_schedule = {
    # Consume WAL every 5 seconds
    'consume-redis-wal': {
        'task': 'api.tasks.consume_redis_wal',
        'schedule': 5.0,  # Every 5 seconds
        'options': {'queue': 'wal_consumer'}
    },
    
    # Fallback DB polling every 10 seconds
    'consume-db-wal': {
        'task': 'api.tasks.consume_db_wal',
        'schedule': 10.0,  # Every 10 seconds
        'options': {'queue': 'wal_consumer'}
    },
    
    # Retry failed entries every minute
    'retry-failed-wal': {
        'task': 'api.tasks.retry_failed_wal_entries',
        'schedule': 60.0,  # Every minute
        'options': {'queue': 'wal_consumer'}
    },
    
    # Cleanup old WAL entries daily at 3 AM
    'cleanup-wal': {
        'task': 'api.tasks.cleanup_old_wal_entries',
        'schedule': crontab(hour=3, minute=0),
        'options': {'queue': 'maintenance'}
    },
    
    # Health check every 30 seconds
    'health-check-wal': {
        'task': 'api.tasks.health_check_wal',
        'schedule': 30.0,  # Every 30 seconds
        'options': {'queue': 'monitoring'}
    },
    
    # Retention and Privacy Tasks
    
    # Cleanup expired data daily at 2 AM
    'cleanup-expired-data': {
        'task': 'api.retention_tasks.cleanup_expired_data',
        'schedule': crontab(hour=2, minute=0),
        'options': {'queue': 'maintenance'}
    },
    
    # Redact PII hourly
    'redact-pii-pipeline': {
        'task': 'api.retention_tasks.redact_pii_pipeline',
        'schedule': crontab(minute=0),  # Every hour
        'options': {'queue': 'privacy'}
    },
    
    # Check consent expirations daily at 1 AM
    'process-consent-expirations': {
        'task': 'api.retention_tasks.process_consent_expirations',
        'schedule': crontab(hour=1, minute=0),
        'options': {'queue': 'privacy'}
    },
}


@app.task(bind=True)
def debug_task(self):
    """Debug task for testing Celery setup."""
    print(f'Request: {self.request!r}')
    return {'status': 'ok', 'message': 'Celery is working!'}
