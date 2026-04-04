#!/usr/bin/env bash
# Celery worker entrypoint
set -e

echo "[celery] Waiting for database..."
python manage.py wait_for_db 2>/dev/null || sleep 5

echo "[celery] Starting Celery worker..."
exec celery -A pentools worker \
    --loglevel=info \
    --concurrency=${CELERY_MAX_CONCURRENCY:-20} \
    --autoscale=${CELERY_MAX_CONCURRENCY:-20},${CELERY_MIN_CONCURRENCY:-4} \
    --max-tasks-per-child=4 \
    --pool=prefork \
    --queues=scan_orchestration,recon_queue,vuln_scan_queue,injection_queue,xss_queue,\
server_audit_queue,web_audit_queue,auth_queue,api_queue,\
business_logic_queue,http_queue,report_queue,notification_queue \
    --hostname=worker@%h
