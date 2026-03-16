"""
Graph WebSocket consumer.
Path: /ws/graph/<project_id>/

Events pushed to browser:
  graph_node_add   — new node (from scan result)
  graph_edge_add   — new edge
  graph_node_update — node data changed (status, finding count)
"""
from __future__ import annotations
import json

from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async


class GraphConsumer(AsyncWebsocketConsumer):

    async def connect(self):
        self.project_id = self.scope["url_route"]["kwargs"]["project_id"]
        self.group_name = f"graph_{self.project_id}"

        user = self.scope.get("user")
        if not user or not user.is_authenticated:
            await self.close(code=4001)
            return

        if not await self._user_can_access(user, self.project_id):
            await self.close(code=4003)
            return

        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(self.group_name, self.channel_name)

    # ── Receive generic messages from browser ──────────────────────────
    async def receive(self, text_data):
        """Browser can request a full refresh."""
        try:
            msg = json.loads(text_data)
        except json.JSONDecodeError:
            return
        if msg.get("action") == "refresh":
            await self._send_full_graph()

    # ── Events pushed by Celery task via channel layer ─────────────────

    async def graph_node_add(self, event):
        await self.send(text_data=json.dumps({
            "type": "node_add",
            "node": event["node"],
        }))

    async def graph_edge_add(self, event):
        await self.send(text_data=json.dumps({
            "type": "edge_add",
            "edge": event["edge"],
        }))

    async def graph_node_update(self, event):
        await self.send(text_data=json.dumps({
            "type": "node_update",
            "node_id": event["node_id"],
            "data": event["data"],
        }))

    async def graph_scan_complete(self, event):
        """Notify browser a scan finished — browser can reload graph data."""
        await self.send(text_data=json.dumps({
            "type": "scan_complete",
            "job_id": event["job_id"],
            "module_id": event.get("module_id", ""),
            "finding_count": event.get("finding_count", 0),
            "status": event.get("status", "done"),
        }))

    # ── Helpers ────────────────────────────────────────────────────────

    @database_sync_to_async
    def _user_can_access(self, user, project_id) -> bool:
        from apps.targets.models import Project
        return Project.objects.filter(
            pk=project_id
        ).filter(
            __import__("django.db.models", fromlist=["Q"]).Q(owner=user) |
            __import__("django.db.models", fromlist=["Q"]).Q(members=user)
        ).exists()

    @database_sync_to_async
    def _get_graph_data(self):
        from apps.targets.models import Project
        from apps.graph.views import build_graph
        try:
            project = Project.objects.get(pk=self.project_id)
            return build_graph(project)
        except Project.DoesNotExist:
            return {"nodes": [], "edges": []}

    async def _send_full_graph(self):
        data = await self._get_graph_data()
        await self.send(text_data=json.dumps({
            "type": "full_graph",
            **data,
        }))
