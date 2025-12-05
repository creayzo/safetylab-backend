#!/bin/bash
#
# Start Celery Worker for AOP
#
# Usage:
#   ./start_worker.sh [queue_name] [concurrency]
#
# Examples:
#   ./start_worker.sh processing 4
#   ./start_worker.sh wal_consumer 2
#

# Configuration
QUEUE=${1:-"processing,wal_consumer,forwarding,websocket"}
CONCURRENCY=${2:-4}
LOGLEVEL=${3:-info}

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Starting Celery Worker...${NC}"
echo -e "Queue: ${YELLOW}$QUEUE${NC}"
echo -e "Concurrency: ${YELLOW}$CONCURRENCY${NC}"
echo -e "Log Level: ${YELLOW}$LOGLEVEL${NC}"
echo ""

# Start worker
celery -A aop worker \
    --queues=$QUEUE \
    --concurrency=$CONCURRENCY \
    --loglevel=$LOGLEVEL \
    --max-tasks-per-child=1000 \
    --time-limit=300 \
    --soft-time-limit=240 \
    --hostname=worker@%h

# Exit codes:
# 0 - Success
# 1 - Error
