from __future__ import absolute_import, unicode_literals
import os
from celery import Celery
from kombu import Queue, Exchange

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "pentools.settings.development")

app = Celery("pentools")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()

# Define all queues explicitly with priorities
default_exchange = Exchange("default", type="direct")

app.conf.task_queues = (
    Queue("scan_orchestration",    default_exchange, routing_key="scan_orchestration",    queue_arguments={"x-max-priority": 10}),
    Queue("recon_queue",           default_exchange, routing_key="recon_queue",           queue_arguments={"x-max-priority": 8}),
    Queue("vuln_scan_queue",       default_exchange, routing_key="vuln_scan_queue",       queue_arguments={"x-max-priority": 8}),
    Queue("injection_queue",       default_exchange, routing_key="injection_queue",       queue_arguments={"x-max-priority": 7}),
    Queue("xss_queue",             default_exchange, routing_key="xss_queue",             queue_arguments={"x-max-priority": 7}),
    Queue("server_audit_queue",    default_exchange, routing_key="server_audit_queue",    queue_arguments={"x-max-priority": 7}),
    Queue("web_audit_queue",       default_exchange, routing_key="web_audit_queue",       queue_arguments={"x-max-priority": 7}),
    Queue("auth_queue",            default_exchange, routing_key="auth_queue",            queue_arguments={"x-max-priority": 7}),
    Queue("api_queue",             default_exchange, routing_key="api_queue",             queue_arguments={"x-max-priority": 7}),
    Queue("business_logic_queue",  default_exchange, routing_key="business_logic_queue",  queue_arguments={"x-max-priority": 6}),
    Queue("http_queue",            default_exchange, routing_key="http_queue",            queue_arguments={"x-max-priority": 6}),
    Queue("report_queue",          default_exchange, routing_key="report_queue",          queue_arguments={"x-max-priority": 4}),
    Queue("notification_queue",    default_exchange, routing_key="notification_queue",    queue_arguments={"x-max-priority": 3}),
)

app.conf.task_default_queue = "web_audit_queue"


@app.task(bind=True)
def debug_task(self):
    print(f"Request: {self.request!r}")
