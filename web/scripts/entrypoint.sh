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

echo "[pentools] Ensuring tool config directories exist..."
for _tool in katana httpx dnsx naabu subfinder nuclei; do
    _dir="/opt/tools/.config/${_tool}"
    if [ ! -d "$_dir" ]; then
        mkdir -p "$_dir" && echo "{}" > "${_dir}/config.yaml" 2>/dev/null || true
    fi
done

echo "[pentools] Ensuring wordlists symlink exists (/opt/tools/wordlists -> /app/wordlists)..."
if [ ! -L /opt/tools/wordlists ]; then
    # Remove stale dir if any, then create symlink
    rm -rf /opt/tools/wordlists 2>/dev/null || true
    ln -s /app/wordlists /opt/tools/wordlists 2>/dev/null || true
fi

echo "[pentools] Ensuring nuclei .local/share symlink exists..."
if [ ! -e /opt/tools/.local/share/nuclei-templates ]; then
    mkdir -p /opt/tools/.local/share 2>/dev/null || true
    ln -sf /opt/tools/nuclei-templates /opt/tools/.local/share/nuclei-templates 2>/dev/null || true
fi

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
