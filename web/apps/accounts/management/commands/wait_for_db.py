"""
Management command: wait_for_db
Polls PostgreSQL until it's ready, then exits.
Used in entrypoint.sh before running migrate.
"""
import time
import logging
from django.core.management.base import BaseCommand
from django.db import connections
from django.db.utils import OperationalError

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Wait for the database to become available"

    def add_arguments(self, parser):
        parser.add_argument(
            "--timeout",
            type=int,
            default=60,
            help="Maximum seconds to wait (default: 60)",
        )
        parser.add_argument(
            "--interval",
            type=float,
            default=1.0,
            help="Seconds between retries (default: 1.0)",
        )

    def handle(self, *args, **options):
        timeout = options["timeout"]
        interval = options["interval"]
        deadline = time.monotonic() + timeout

        self.stdout.write("Waiting for database...")
        while True:
            try:
                conn = connections["default"]
                conn.ensure_connection()
                self.stdout.write(self.style.SUCCESS("Database available."))
                return
            except OperationalError as exc:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self.stderr.write(
                        self.style.ERROR(
                            f"Database not available after {timeout}s: {exc}"
                        )
                    )
                    raise SystemExit(1)
                self.stdout.write(
                    f"  DB unavailable ({exc}), retrying in {interval}s "
                    f"({remaining:.0f}s remaining)..."
                )
                time.sleep(interval)
