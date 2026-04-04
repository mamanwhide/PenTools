"""
Celery task: poll Telegram Bot API for new commands (getUpdates long-poll).

Scheduled every 3 seconds via CELERY_BEAT_SCHEDULE in pentools/celery.py.
Uses Django's cache backend (Redis) to persist the update offset across runs.
"""
from __future__ import annotations

import logging
from celery import shared_task
from django.core.cache import cache

logger = logging.getLogger(__name__)

_OFFSET_KEY = "tgbot:update_offset"


@shared_task(
    name="notifications.poll_telegram_bot",
    queue="notification_queue",
    ignore_result=True,
    max_retries=0,
    time_limit=10,
)
def poll_telegram_bot() -> None:
    """
    Fetch new Telegram updates and dispatch each one to the bot command handler.

    Uses the stored offset so each update is processed exactly once.
    Silently skips when TELEGRAM_BOT_TOKEN is not configured.

    A Redis lock prevents concurrent executions (HTTP 409 from Telegram when two
    getUpdates requests run simultaneously against the same bot token).
    """
    from .bot import get_bot_token, handle_update

    import requests

    token = get_bot_token()
    if not token:
        return  # bot not configured — nothing to do

    # Acquire an exclusive lock for the duration of this poll cycle.
    # TTL slightly longer than time_limit so a crashed task still releases the lock.
    lock_key = "tgbot:poll_lock"
    if not cache.add(lock_key, 1, timeout=12):
        return  # another worker is already polling — skip this invocation

    try:
        offset = cache.get(_OFFSET_KEY, 0)

        try:
            resp = requests.get(
                f"https://api.telegram.org/bot{token}/getUpdates",
                params={"offset": offset, "timeout": 0, "limit": 100},
                timeout=8,
            )
        except requests.RequestException as exc:
            logger.warning("Telegram getUpdates network error: %s", exc)
            return

        if not resp.ok:
            logger.warning("Telegram getUpdates HTTP %s: %s", resp.status_code, resp.text[:200])
            return

        data = resp.json()
        if not data.get("ok"):
            logger.warning("Telegram API returned ok=false: %s", data)
            return

        updates = data.get("result", [])
        if not updates:
            return

        new_offset = offset
        for update in updates:
            update_id = update.get("update_id", 0)
            if update_id >= new_offset:
                new_offset = update_id + 1
            try:
                handle_update(update)
            except Exception as exc:
                logger.error("Error handling Telegram update %s: %s", update_id, exc, exc_info=True)

        if new_offset > offset:
            # Persist offset with no expiry so it survives Redis restarts
            cache.set(_OFFSET_KEY, new_offset, timeout=86400 * 30)
    finally:
        cache.delete(lock_key)
