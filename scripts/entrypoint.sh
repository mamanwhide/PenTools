#!/usr/bin/env bash
# Django application entrypoint
set -e

echo "[pentools] Waiting for database..."
python manage.py wait_for_db 2>/dev/null || sleep 5

echo "[pentools] Running migrations..."
python manage.py migrate --noinput

echo "[pentools] Collecting static files..."
python manage.py collectstatic --noinput --clear 2>&1 || {
    echo "[pentools] collectstatic failed (likely permission issue on volume), trying with mkdir..."
    mkdir -p /app/staticfiles
    python manage.py collectstatic --noinput --clear 2>&1 || true
}

echo "[pentools] Loading initial data..."
python manage.py loaddata initial_wordlists 2>/dev/null || true

echo "[pentools] Starting ASGI server (Uvicorn via Gunicorn)..."
exec gunicorn pentools.asgi:application \
    --worker-class uvicorn.workers.UvicornWorker \
    --workers 4 \
    --bind 0.0.0.0:8000 \
    --timeout 120 \
    --keep-alive 5 \
    --log-level info \
    --access-logfile - \
    --error-logfile -
