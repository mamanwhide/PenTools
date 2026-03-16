"""
Integration test suite for VulnX PenTools.

Covers the complete user flow:
  1. Health check
  2. Authentication (login / logout / profile / API key regen)
  3. Project and target management
  4. Module registry (list, detail, schema integrity)
  5. Scan lifecycle (create, detail, status API, cancel, retry)
  6. Findings (create, list, filter, detail, edit, status update, CVSS calculator, duplicate detection)
  7. Reports (create, detail, builder, download endpoints)
  8. Notifications (channel create)
  9. Dashboard stats
 10. REST API endpoints (job status, logs, findings, saved configs)

Run inside the container:
    docker compose exec web python manage.py test tests.test_integration_flow --verbosity=2
"""

import json
import uuid

from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from django.urls import reverse

from apps.targets.models import Project, Target
from apps.scans.models import ScanJob, ScanLog, ScanJobTemplate
from apps.results.models import Finding

User = get_user_model()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mk_user(username="testuser", password="TestPass123!", role="operator"):
    user = User.objects.create_user(username=username, password=password, email=f"{username}@example.com")
    user.role = role
    user.save()
    return user, password


def _mk_project(owner, name="Test Project"):
    return Project.objects.create(owner=owner, name=name)


def _mk_target(project, name="example", value="https://example.com"):
    return Target.objects.create(
        project=project,
        name=name,
        value=value,
        target_type=Target.TargetType.URL,
        created_by=project.owner,
    )


def _mk_scan(user, module_id="AUTH-01", project=None, target=None, status="done"):
    job = ScanJob.objects.create(
        module_id=module_id,
        params={"target_url": "https://example.com"},
        created_by=user,
        project=project,
        target=target,
        status=status,
        finding_count=2,
        critical_count=1,
        high_count=1,
    )
    return job


def _mk_finding(job=None, project=None, user=None, severity="high"):
    return Finding.objects.create(
        scan_job=job,
        project=project or (job.project if job else None),
        title=f"Test Finding [{severity}]",
        severity=severity,
        url="https://example.com/vuln",
        description="Vulnerability description.",
        evidence="HTTP 200 response with payload reflected.",
        remediation="Sanitise input.",
        created_by=user,
        status=Finding.Status.OPEN,
    )


# ===========================================================================
# 1. Health Check
# ===========================================================================

class HealthCheckTestCase(TestCase):
    def test_health_endpoint_returns_200(self):
        c = Client()
        resp = c.get("/health/")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.content)
        self.assertEqual(data.get("status"), "ok")


# ===========================================================================
# 2. Authentication Flow
# ===========================================================================

class AuthenticationTestCase(TestCase):
    def setUp(self):
        self.user, self.password = _mk_user()
        self.c = Client()

    def test_login_page_renders(self):
        resp = self.c.get("/login/")
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "VulnX")

    def test_login_with_valid_credentials(self):
        resp = self.c.post("/login/", {"username": self.user.username, "password": self.password}, follow=True)
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.wsgi_request.user.is_authenticated)

    def test_login_with_invalid_credentials_stays_on_login(self):
        resp = self.c.post("/login/", {"username": self.user.username, "password": "wrong"}, follow=True)
        self.assertFalse(resp.wsgi_request.user.is_authenticated)

    def test_unauthenticated_dashboard_redirects_to_login(self):
        resp = self.c.get("/dashboard/")
        self.assertRedirects(resp, "/login/?next=/dashboard/", fetch_redirect_response=False)

    def test_logout_clears_session(self):
        self.c.login(username=self.user.username, password=self.password)
        resp = self.c.post("/logout/", follow=True)
        self.assertFalse(resp.wsgi_request.user.is_authenticated)

    def test_profile_page_requires_auth(self):
        resp = self.c.get("/profile/", follow=True)
        self.assertIn("/login/", resp.redirect_chain[0][0])

    def test_profile_page_renders_when_authenticated(self):
        self.c.login(username=self.user.username, password=self.password)
        resp = self.c.get("/profile/")
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, self.user.username)

    def test_regenerate_api_key(self):
        self.c.login(username=self.user.username, password=self.password)
        old_key = self.user.api_key
        resp = self.c.post("/profile/regenerate-key/", follow=True)
        self.assertEqual(resp.status_code, 200)
        self.user.refresh_from_db()
        self.assertNotEqual(self.user.api_key, old_key)


# ===========================================================================
# 3. Project and Target Management
# ===========================================================================

class ProjectTargetTestCase(TestCase):
    def setUp(self):
        self.user, self.password = _mk_user("projuser")
        self.c = Client()
        self.c.login(username=self.user.username, password=self.password)

    def test_project_list_renders(self):
        resp = self.c.get("/targets/")
        self.assertEqual(resp.status_code, 200)

    def test_create_project(self):
        resp = self.c.post("/targets/new/", {
            "name": "My Engagement",
            "description": "Test engagement scope",
        }, follow=True)
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(Project.objects.filter(name="My Engagement", owner=self.user).exists())

    def test_project_detail_renders(self):
        project = _mk_project(self.user)
        resp = self.c.get(f"/targets/{project.id}/")
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, project.name)

    def test_add_target_to_project(self):
        project = _mk_project(self.user)
        resp = self.c.post(f"/targets/{project.id}/targets/new/", {
            "name": "Main App",
            "target_type": "url",
            "value": "https://target.example.com",
        }, follow=True)
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(Target.objects.filter(project=project, value="https://target.example.com").exists())

    def test_target_uniqueness_per_project(self):
        project = _mk_project(self.user)
        _mk_target(project)
        with self.assertRaises(Exception):
            _mk_target(project)  # same project + value => IntegrityError

    def test_delete_project(self):
        project = _mk_project(self.user, name="ToDelete")
        resp = self.c.post(f"/targets/{project.id}/delete/", follow=True)
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(Project.objects.filter(id=project.id).exists())

    def test_delete_target(self):
        project = _mk_project(self.user)
        target = _mk_target(project)
        resp = self.c.post(f"/targets/targets/{target.id}/delete/", follow=True)
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(Target.objects.filter(id=target.id).exists())


# ===========================================================================
# 4. Module Registry
# ===========================================================================

class ModuleRegistryTestCase(TestCase):
    def setUp(self):
        self.user, self.password = _mk_user("moduser")
        self.c = Client()
        self.c.login(username=self.user.username, password=self.password)

    def test_module_list_renders(self):
        resp = self.c.get("/modules/")
        self.assertEqual(resp.status_code, 200)

    def test_module_list_with_category_filter(self):
        resp = self.c.get("/modules/?category=recon")
        self.assertEqual(resp.status_code, 200)

    def test_module_list_with_search(self):
        resp = self.c.get("/modules/?q=jwt")
        self.assertEqual(resp.status_code, 200)

    def test_module_detail_renders_for_known_module(self):
        resp = self.c.get("/modules/AUTH-01/")
        self.assertEqual(resp.status_code, 200)

    def test_module_detail_404_for_unknown_module(self):
        resp = self.c.get("/modules/DOES-NOT-EXIST/")
        self.assertEqual(resp.status_code, 404)

    def test_api_module_list_returns_json(self):
        resp = self.c.get("/api/v1/modules/")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.content)
        # The modules API returns {"count": N, "results": [...]}
        self.assertIn("results", data)
        self.assertGreater(data["count"], 0)

    def test_all_modules_have_required_fields(self):
        from apps.modules.engine import ModuleRegistry
        registry = ModuleRegistry.instance()
        for module in registry.all():
            with self.subTest(module_id=module.id):
                self.assertTrue(module.id)
                self.assertTrue(module.name)
                self.assertTrue(module.category)
                self.assertIsInstance(module.PARAMETER_SCHEMA, list)
                self.assertIn(module.risk_level, ("critical", "high", "medium", "low", "info"))

    def test_module_schema_has_valid_field_types(self):
        from apps.modules.engine import ModuleRegistry, FIELD_TYPES
        registry = ModuleRegistry.instance()
        for module in registry.all():
            for field in module.PARAMETER_SCHEMA:
                with self.subTest(module_id=module.id, field=field.key):
                    self.assertIn(field.field_type, FIELD_TYPES,
                                  f"{module.id}.{field.key} has invalid type '{field.field_type}'")


# ===========================================================================
# 5. Scan Lifecycle
# ===========================================================================

class ScanLifecycleTestCase(TestCase):
    def setUp(self):
        self.user, self.password = _mk_user("scanuser")
        self.project = _mk_project(self.user)
        self.target = _mk_target(self.project)
        self.c = Client()
        self.c.login(username=self.user.username, password=self.password)

    def test_scan_create_form_renders(self):
        resp = self.c.get("/scans/new/AUTH-01/")
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Launch Scan")

    def test_scan_create_form_404_for_unknown_module(self):
        resp = self.c.get("/scans/new/FAKE-99/")
        self.assertEqual(resp.status_code, 404)

    def test_scan_create_post_creates_job(self):
        resp = self.c.post("/scans/new/AUTH-01/", {
            "target_url": "https://example.com",
            "project_id": str(self.project.id),
            "target_id": str(self.target.id),
            "attacks": ["alg_none", "weak_secret"],
        }, follow=False)
        # Should redirect to scan detail
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/scans/", resp["Location"])
        job_id = resp["Location"].strip("/").split("/")[-1].rstrip("/")
        self.assertTrue(ScanJob.objects.filter(id=job_id).exists())

    def test_scan_detail_renders(self):
        job = _mk_scan(self.user, project=self.project)
        resp = self.c.get(f"/scans/{job.id}/")
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, job.module_id)

    def test_scan_detail_403_for_other_user(self):
        other, _ = _mk_user("otheruser")
        job = _mk_scan(other)
        resp = self.c.get(f"/scans/{job.id}/")
        self.assertEqual(resp.status_code, 404)

    def test_scan_list_renders(self):
        resp = self.c.get("/scans/")
        self.assertEqual(resp.status_code, 200)

    def test_scan_list_status_filter(self):
        done_job = _mk_scan(self.user, status="done")
        failed_job = _mk_scan(self.user, module_id="XSS-01", status="failed")
        resp = self.c.get("/scans/?status=done")
        self.assertEqual(resp.status_code, 200)
        # Only the done job should appear; the failed job should not.
        self.assertContains(resp, str(done_job.id))
        self.assertNotContains(resp, str(failed_job.id))

    def test_scan_cancel_running_job(self):
        # A running job must have a celery_task_id for the cancel to take effect.
        job = _mk_scan(self.user, status="running")
        job.celery_task_id = "fake-celery-id-for-test"
        job.save(update_fields=["celery_task_id"])
        resp = self.c.post(f"/scans/{job.id}/cancel/")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.content)
        self.assertTrue(data.get("ok"))
        job.refresh_from_db()
        self.assertEqual(job.status, "cancelled")

    def test_scan_cancel_already_done_has_no_effect(self):
        job = _mk_scan(self.user, status="done")
        resp = self.c.post(f"/scans/{job.id}/cancel/")
        self.assertEqual(resp.status_code, 200)
        job.refresh_from_db()
        self.assertEqual(job.status, "done")  # stays done

    def test_scan_retry_failed_creates_new_job(self):
        job = _mk_scan(self.user, status="failed")
        count_before = ScanJob.objects.filter(created_by=self.user).count()
        resp = self.c.post(f"/scans/{job.id}/retry/", follow=False)
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(ScanJob.objects.filter(created_by=self.user).count(), count_before + 1)

    def test_scan_retry_rejects_non_failed_job(self):
        job = _mk_scan(self.user, status="done")
        resp = self.c.post(f"/scans/{job.id}/retry/")
        self.assertEqual(resp.status_code, 400)


# ===========================================================================
# 6. REST API — Job Status / Logs / Findings / Configs
# ===========================================================================

class ScanAPITestCase(TestCase):
    def setUp(self):
        self.user, self.password = _mk_user("apiuser")
        self.project = _mk_project(self.user)
        self.job = _mk_scan(self.user, project=self.project)
        self.c = Client()
        self.c.login(username=self.user.username, password=self.password)
        ScanLog.objects.create(scan_job=self.job, level="info", message="Test log line")

    def test_api_job_status(self):
        resp = self.c.get(f"/api/v1/scans/{self.job.id}/status/")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.content)
        self.assertEqual(data["status"], "done")
        self.assertIn("progress", data)
        self.assertIn("finding_count", data)

    def test_api_job_logs(self):
        resp = self.c.get(f"/api/v1/scans/{self.job.id}/logs/")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.content)
        self.assertEqual(len(data["logs"]), 1)
        self.assertEqual(data["logs"][0]["message"], "Test log line")

    def test_api_job_logs_since_param(self):
        log = ScanLog.objects.get(scan_job=self.job)
        resp = self.c.get(f"/api/v1/scans/{self.job.id}/logs/?since={log.id}")
        data = json.loads(resp.content)
        self.assertEqual(len(data["logs"]), 0)  # nothing newer

    def test_api_job_findings(self):
        _mk_finding(job=self.job)
        resp = self.c.get(f"/api/v1/scans/{self.job.id}/findings/")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.content)
        self.assertEqual(len(data["findings"]), 1)

    def test_api_status_requires_auth(self):
        anon = Client()
        resp = anon.get(f"/api/v1/scans/{self.job.id}/status/")
        self.assertIn(resp.status_code, (302, 401, 403))

    def test_api_save_and_load_config(self):
        payload = {"name": "my-config", "params": {"target_url": "https://example.com"}}
        resp = self.c.post(
            f"/api/v1/scans/configs/AUTH-01/save/",
            data=json.dumps(payload),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.content)
        self.assertTrue(data["ok"])

        resp2 = self.c.get("/api/v1/scans/configs/AUTH-01/")
        self.assertEqual(resp2.status_code, 200)
        list_data = json.loads(resp2.content)
        self.assertEqual(len(list_data["templates"]), 1)
        self.assertEqual(list_data["templates"][0]["name"], "my-config")

    def test_api_config_unique_per_name(self):
        payload = {"name": "dup-config", "params": {"target_url": "https://a.com"}}
        self.c.post("/api/v1/scans/configs/AUTH-01/save/",
                    data=json.dumps(payload), content_type="application/json")
        payload2 = {"name": "dup-config", "params": {"target_url": "https://b.com"}}
        resp = self.c.post("/api/v1/scans/configs/AUTH-01/save/",
                           data=json.dumps(payload2), content_type="application/json")
        self.assertEqual(resp.status_code, 200)
        # Should update, not create duplicate
        self.assertEqual(ScanJobTemplate.objects.filter(
            module_id="AUTH-01", name="dup-config", created_by=self.user
        ).count(), 1)

    def test_api_delete_config(self):
        ScanJobTemplate.objects.create(
            module_id="AUTH-01", name="to-delete",
            params={}, created_by=self.user,
        )
        tpl = ScanJobTemplate.objects.get(name="to-delete", created_by=self.user)
        resp = self.c.post(f"/api/v1/scans/configs/delete/{tpl.id}/")
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(ScanJobTemplate.objects.filter(id=tpl.id).exists())


# ===========================================================================
# 7. Findings
# ===========================================================================

class FindingsTestCase(TestCase):
    def setUp(self):
        self.user, self.password = _mk_user("findinguser")
        self.project = _mk_project(self.user)
        self.job = _mk_scan(self.user, project=self.project)
        self.c = Client()
        self.c.login(username=self.user.username, password=self.password)

    def test_finding_list_renders(self):
        resp = self.c.get("/findings/")
        self.assertEqual(resp.status_code, 200)

    def test_finding_list_filter_by_severity(self):
        _mk_finding(job=self.job, user=self.user, severity="critical")
        _mk_finding(job=self.job, user=self.user, severity="low")
        resp = self.c.get("/findings/?severity=critical")
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "critical")
        self.assertNotContains(resp, "Test Finding [low]")

    def test_finding_list_filter_by_status(self):
        f = _mk_finding(job=self.job, user=self.user)
        f.status = Finding.Status.FIXED
        f.save()
        resp = self.c.get("/findings/?status=open")
        self.assertEqual(resp.status_code, 200)
        self.assertNotContains(resp, "Test Finding [high]")

    def test_manual_finding_create(self):
        resp = self.c.post("/findings/create/", {
            "project": str(self.project.id),
            "title": "Manual SQL Injection",
            "severity": "high",
            "url": "https://example.com/search",
            "description": "SQL injection via search parameter.",
            "evidence": "' OR 1=1--",
            "remediation": "Use parameterised queries.",
            "status": "open",
        }, follow=True)
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(Finding.objects.filter(title="Manual SQL Injection").exists())
        finding = Finding.objects.get(title="Manual SQL Injection")
        self.assertTrue(finding.is_manual)

    def test_finding_detail_renders(self):
        finding = _mk_finding(job=self.job, user=self.user)
        resp = self.c.get(f"/findings/{finding.id}/")
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, finding.title)

    def test_finding_edit(self):
        finding = _mk_finding(job=self.job, user=self.user)
        resp = self.c.post(f"/findings/{finding.id}/edit/", {
            "title": "Updated Title",
            "severity": "critical",
            "url": finding.url,
            "description": finding.description,
            "evidence": finding.evidence,
            "remediation": finding.remediation,
            "status": "confirmed",
        }, follow=True)
        self.assertEqual(resp.status_code, 200)
        finding.refresh_from_db()
        self.assertEqual(finding.title, "Updated Title")
        self.assertEqual(finding.severity, "critical")

    def test_finding_status_update(self):
        finding = _mk_finding(job=self.job, user=self.user)
        # The status update view reads request.POST, not JSON.
        resp = self.c.post(f"/findings/{finding.id}/status/", {"status": "fixed"})
        self.assertEqual(resp.status_code, 200)
        finding.refresh_from_db()
        self.assertEqual(finding.status, "fixed")

    def test_finding_duplicate_detection(self):
        finding = _mk_finding(job=self.job, user=self.user)
        resp = self.c.get("/findings/check-duplicate/", {
            "title": finding.title,
            "url": finding.url,
            "evidence": finding.evidence[:200],
            "project": str(self.project.id),
        })
        self.assertEqual(resp.status_code, 200)

    def test_finding_evidence_hash_dedup(self):
        f1 = _mk_finding(job=self.job, user=self.user)
        f2 = Finding.objects.create(
            scan_job=self.job, project=self.project,
            title=f1.title, severity=f1.severity,
            url=f1.url, evidence=f1.evidence,
            remediation=f1.remediation, created_by=self.user,
        )
        self.assertEqual(f1.evidence_hash, f2.evidence_hash)
        self.assertTrue(f2.is_duplicate)

    def test_cvss_calculator_renders(self):
        resp = self.c.get("/findings/cvss-calculator/")
        self.assertEqual(resp.status_code, 200)

    def test_cvss_calculator_htmx_partial(self):
        resp = self.c.get("/findings/cvss-calculator/", {
            "AV": "N", "AC": "L", "PR": "N", "UI": "N",
            "S": "U", "C": "H", "I": "H", "A": "H",
        }, HTTP_HX_REQUEST="true")
        self.assertEqual(resp.status_code, 200)


# ===========================================================================
# 8. Reports
# ===========================================================================

class ReportsTestCase(TestCase):
    def setUp(self):
        self.user, self.password = _mk_user("reportuser")
        self.project = _mk_project(self.user)
        self.job = _mk_scan(self.user, project=self.project)
        self.finding = _mk_finding(job=self.job, user=self.user, severity="critical")
        self.c = Client()
        self.c.login(username=self.user.username, password=self.password)

    def test_report_list_renders(self):
        resp = self.c.get("/reports/")
        self.assertEqual(resp.status_code, 200)

    def test_create_report(self):
        from apps.reports.models import Report
        resp = self.c.post("/reports/create/", {
            "project": str(self.project.id),
            "title": "Security Assessment Report",
            "executive_summary": "Executive summary text.",
            "min_severity": "medium",
        }, follow=True)
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(Report.objects.filter(title="Security Assessment Report").exists())

    def test_report_detail_renders(self):
        from apps.reports.models import Report
        report = Report.objects.create(
            project=self.project,
            title="Test Report",
            created_by=self.user,
        )
        resp = self.c.get(f"/reports/{report.id}/")
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Test Report")

    def test_report_builder_renders(self):
        from apps.reports.models import Report
        report = Report.objects.create(
            project=self.project, title="Build Report", created_by=self.user,
        )
        resp = self.c.get(f"/reports/{report.id}/builder/")
        self.assertEqual(resp.status_code, 200)


# ===========================================================================
# 9. Notifications
# ===========================================================================

class NotificationsTestCase(TestCase):
    def setUp(self):
        self.user, self.password = _mk_user("notifuser")
        self.project = _mk_project(self.user)
        self.c = Client()
        self.c.login(username=self.user.username, password=self.password)

    def test_notification_list_renders(self):
        resp = self.c.get("/notifications/")
        self.assertEqual(resp.status_code, 200)

    def test_create_telegram_channel(self):
        from apps.notifications.models import NotificationChannel
        resp = self.c.post("/notifications/create/", {
            "channel_type": "telegram",
            "name": "Alert Channel",
            "telegram_bot_token": "123:TEST",
            "telegram_chat_id": "-100123",
            "project": str(self.project.id),
            "trigger_events": ["scan_complete", "critical_finding"],
            "is_active": True,
        }, follow=True)
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(NotificationChannel.objects.filter(name="Alert Channel").exists())


# ===========================================================================
# 10. Dashboard
# ===========================================================================

class DashboardTestCase(TestCase):
    def setUp(self):
        self.user, self.password = _mk_user("dashuser")
        self.project = _mk_project(self.user)
        self.c = Client()
        self.c.login(username=self.user.username, password=self.password)

    def test_dashboard_renders_with_no_data(self):
        resp = self.c.get("/dashboard/")
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Dashboard")
        self.assertContains(resp, "0")  # zero stats

    def test_dashboard_shows_scan_stats(self):
        _mk_scan(self.user, project=self.project, status="done")
        resp = self.c.get("/dashboard/")
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "1")  # scans_total

    def test_dashboard_shows_recent_scans(self):
        job = _mk_scan(self.user, project=self.project, status="done")
        resp = self.c.get("/dashboard/")
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, job.module_id)

    def test_dashboard_redirects_at_root(self):
        resp = self.c.get("/")
        self.assertRedirects(resp, "/dashboard/", fetch_redirect_response=False)

    def test_dashboard_only_shows_own_scans(self):
        other, _ = _mk_user("outsider")
        _mk_scan(other, module_id="XSS-01")
        resp = self.c.get("/dashboard/")
        self.assertNotContains(resp, "XSS-01")

    def test_dashboard_stat_aggregation(self):
        job = ScanJob.objects.create(
            module_id="AUTH-01",
            params={},
            created_by=self.user,
            status="done",
            critical_count=3,
            high_count=5,
        )
        resp = self.c.get("/dashboard/")
        self.assertContains(resp, "3")  # critical
        self.assertContains(resp, "5")  # high


# ===========================================================================
# 11. Context Processor — user_all_projects
# ===========================================================================

class ContextProcessorTestCase(TestCase):
    def setUp(self):
        self.owner, self.owner_pass = _mk_user("cpowner")
        self.member, self.member_pass = _mk_user("cpmember")
        self.owned_project = _mk_project(self.owner, name="Owned Project")
        self.member_project = _mk_project(self.owner, name="Member Project")
        self.member_project.members.add(self.member)
        self.c = Client()

    def test_owner_sees_own_projects_in_switcher(self):
        self.c.login(username=self.owner.username, password=self.owner_pass)
        resp = self.c.get("/dashboard/")
        self.assertContains(resp, "Owned Project")
        self.assertContains(resp, "Member Project")

    def test_member_sees_member_projects_in_switcher(self):
        self.c.login(username=self.member.username, password=self.member_pass)
        resp = self.c.get("/dashboard/")
        self.assertContains(resp, "Member Project")
        self.assertNotContains(resp, "Owned Project")


# ===========================================================================
# 12. Scan Parameter Validation
# ===========================================================================

class ScanParamValidationTestCase(TestCase):
    def setUp(self):
        self.user, self.password = _mk_user("validuser")
        self.c = Client()
        self.c.login(username=self.user.username, password=self.password)

    def test_scan_without_required_url_still_creates_job(self):
        """The view accepts any params; module validates on execution."""
        resp = self.c.post("/scans/new/AUTH-01/", {
            "target_url": "",
        }, follow=False)
        self.assertEqual(resp.status_code, 302)

    def test_scan_module_schema_to_dict_is_serializable(self):
        from apps.modules.engine import ModuleRegistry
        registry = ModuleRegistry.instance()
        for module in registry.all():
            with self.subTest(module_id=module.id):
                schema = module.schema_to_dict()
                # Must be JSON-serializable (no datetime, UUID, etc.)
                json.dumps(schema)


# ===========================================================================
# 13. Scan Tasks — execute_module function (unit)
# ===========================================================================

class ScanTaskUnitTestCase(TestCase):
    def setUp(self):
        self.user, _ = _mk_user("taskuser")
        self.project = _mk_project(self.user)

    def test_task_marks_job_failed_for_nonexistent_module(self):
        """If the module_id no longer resolves, the task must fail gracefully."""
        from apps.scans.tasks import execute_module
        job = ScanJob.objects.create(
            module_id="NONEXISTENT-MODULE",
            params={},
            created_by=self.user,
            status=ScanJob.Status.PENDING,
            celery_task_id="test-placeholder-task-id",
        )
        # Run synchronously (bypasses Celery broker)
        execute_module(str(job.id))
        job.refresh_from_db()
        self.assertEqual(job.status, ScanJob.Status.FAILED)


# ===========================================================================
# 14. Finding model — computed properties
# ===========================================================================

class FindingModelTestCase(TestCase):
    def setUp(self):
        self.user, _ = _mk_user("modeluser")
        self.project = _mk_project(self.user)

    def test_evidence_hash_is_computed_on_save(self):
        f = _mk_finding(project=self.project, user=self.user)
        self.assertEqual(len(f.evidence_hash), 64)  # SHA-256 hex

    def test_severity_badge_class_returns_string(self):
        for sev in ("critical", "high", "medium", "low", "info"):
            f = Finding.objects.create(
                project=self.project, title="T", severity=sev,
                url="https://x.com", created_by=self.user,
            )
            self.assertIsInstance(f.severity_badge_class, str)

    def test_finding_auto_inherits_project_from_scan(self):
        job = _mk_scan(self.user, project=self.project)
        f = Finding.objects.create(
            scan_job=job, title="Auto", severity="info",
            url="https://x.com", created_by=self.user,
        )
        self.assertEqual(f.project, self.project)
