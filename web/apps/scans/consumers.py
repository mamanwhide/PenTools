"""
WebSocket consumer for real-time scan log streaming.
Path: /ws/scan/<job_id>/
"""
import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async


class ScanLogConsumer(AsyncWebsocketConsumer):

    async def connect(self):
        self.job_id = self.scope["url_route"]["kwargs"]["job_id"]
        self.group_name = f"scan_{self.job_id}"

        user = self.scope.get("user")
        if not user or not user.is_authenticated:
            await self.close(code=4001)
            return

        if not await self._user_can_access(user, self.job_id):
            await self.close(code=4003)
            return

        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

        # Send buffered logs for reconnection (last 200 lines)
        await self._send_history()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(self.group_name, self.channel_name)

    # ── Receive events from Celery task via channel layer ──────────────

    async def scan_log(self, event):
        """Forward a log line to the connected browser."""
        await self.send(text_data=json.dumps({
            "type": "log",
            "level": event["level"],
            "message": event["message"],
            "timestamp": event["timestamp"],
        }))

    async def scan_progress(self, event):
        """Forward progress update."""
        await self.send(text_data=json.dumps({
            "type": "progress",
            "progress": event["progress"],
            "status": event["status"],
        }))

    async def scan_complete(self, event):
        """Notify browser that scan finished."""
        await self.send(text_data=json.dumps({
            "type": "complete",
            "status": event["status"],
            "finding_count": event.get("finding_count", 0),
            "duration": event.get("duration"),
        }))

    async def graph_update(self, event):
        """Push new graph nodes/edges after scan completes."""
        await self.send(text_data=json.dumps({
            "type": "graph_update",
            "nodes": event.get("nodes", []),
            "edges": event.get("edges", []),
        }))

    # ── Helpers ────────────────────────────────────────────────────────

    @database_sync_to_async
    def _user_can_access(self, user, job_id) -> bool:
        from apps.scans.models import ScanJob
        try:
            job = ScanJob.objects.get(id=job_id)
            return job.created_by_id == user.id or user.is_admin_role
        except ScanJob.DoesNotExist:
            return False

    @database_sync_to_async
    def _get_history_logs(self, job_id):
        from apps.scans.models import ScanLog
        return list(
            ScanLog.objects.filter(scan_job_id=job_id)
            .order_by("-timestamp")[:200]
            .values("level", "message", "timestamp")
        )

    async def _send_history(self):
        logs = await self._get_history_logs(self.job_id)
        for log in reversed(logs):
            await self.send(text_data=json.dumps({
                "type": "log",
                "level": log["level"],
                "message": log["message"],
                "timestamp": log["timestamp"].isoformat(),
                "historical": True,
            }))
