#!/bin/bash
#
# Start Celery Beat Scheduler
#
# Celery Beat runs periodic tasks on schedule:
# - WAL consumption
# - Failed entry retries
# - Cleanup tasks
# - Health checks
#

# Colors
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${GREEN}Starting Celery Beat Scheduler...${NC}"
echo ""

# Start beat
celery -A aop beat \
    --loglevel=info \
    --scheduler=django_celery_beat.schedulers:DatabaseScheduler

# Note: For production, use --pidfile and --logfile
# celery -A aop beat \
#     --loglevel=info \
#     --pidfile=/var/run/celerybeat.pid \
#     --logfile=/var/log/celery/beat.log
