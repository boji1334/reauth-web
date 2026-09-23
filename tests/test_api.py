"""HTTP 层：提交校验、任务状态、下载路由（不打真实网络）。"""

from __future__ import annotations

import json
import unittest

from fastapi.testclient import TestClient

from app import main as site

SECRET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


class ApiTests(unittest.TestCase):
    def setUp(self):
        site.submit_limiter.hits.clear()
        site.api_limiter.hits.clear()
        self.client = TestClient(site.app)
        self.token = self.client.get("/api/session").json()["token"]

    def auth_headers(self, token: str | None = None) -> dict:
        value = self.token if token is None else token
        return {"X-REAUTH-TOKEN": value}

    def test_health(self):
        body = self.client.get("/api/health").json()
        self.assertTrue(body["ok"])

    def test_meta_exposes_limits(self):
        body = self.client.get("/api/meta").json()
        self.assertIn("max_accounts", body)
        self.assertIn("sub2-merged", body["outputs"])
        self.assertEqual(body["github_url"], "")
        self.assertIn("reauth", body["steps"])
        self.assertIn("cache_ttl_seconds", body)

    def test_visit_endpoint_counts(self):
        first = self.client.post("/api/visit", json={"visitor_id": "t-1"}).json()
        self.assertTrue(first["ok"])
        self.assertGreaterEqual(first["today_visitors"], 1)
        self.assertGreaterEqual(first["today_visits"], 1)
        snapshot = self.client.get("/api/visit").json()
        self.assertEqual(len(snapshot["days"]), 7)

    def test_convert_endpoint_returns_immediately(self):
        from tests.test_convert import sub2_account

        payload = {"accounts": [sub2_account("api@b.com", "plus")]}
        resp = self.client.post(
            "/api/convert",
            json={"text": json.dumps(payload)},
            headers=self.auth_headers(),
        )
        self.assertEqual(resp.status_code, 200, resp.text)
        snap = resp.json()
        self.assertTrue(snap["finished"])
        self.assertEqual(snap["ok"], 1)
        self.assertEqual(snap["total"], 1)
        self.assertEqual(snap["mode"], "convert")
        # 三个步骤都是完成态
        self.assertEqual(
            [step["status"] for step in snap["accounts"][0]["steps"]],
            ["done", "done", "done"],
        )
        for kind in ("cpa", "sub2-merged", "sub2-single", "cockpit"):
            download = self.client.get(f"/api/job/{snap['job_id']}/download/{kind}")
            self.assertEqual(download.status_code, 200, kind)

    def test_convert_endpoint_rejects_non_sub2_json(self):
        resp = self.client.post(
            "/api/convert",
            json={"text": '{"hello": 1}'},
            headers=self.auth_headers(),
        )
        self.assertEqual(resp.status_code, 422)

    def test_submit_requires_session_token(self):
        resp = self.client.post(
            "/api/submit",
            json={"text": "a@b.com----pw----ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", "mode": "reauth"},
        )
        self.assertEqual(resp.status_code, 403)

    def test_forged_token_is_rejected(self):
        resp = self.client.post(
            "/api/submit",
            json={"text": "bad", "mode": "reauth"},
            headers=self.auth_headers("forged.0000"),
        )
        self.assertEqual(resp.status_code, 403)

    def test_robots_txt_blocks_crawlers(self):
        resp = self.client.get("/robots.txt")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Disallow: /", resp.text)

    def test_security_headers_present(self):
        resp = self.client.get("/")
        self.assertEqual(resp.headers["x-frame-options"], "DENY")
        self.assertIn("frame-ancestors", resp.headers["content-security-policy"])
        self.assertEqual(resp.headers["referrer-policy"], "no-referrer")

    def test_submit_rate_limited(self):
        site.submit_limiter.hits.clear()
        site.submit_limiter.limit = 2
        try:
            for _ in range(2):
                resp = self.client.post(
                    "/api/submit",
                    json={"text": "", "mode": "reauth"},
                    headers=self.auth_headers(),
                )
                self.assertEqual(resp.status_code, 422, resp.text)
            blocked = self.client.post(
                "/api/submit",
                json={"text": "", "mode": "reauth"},
                headers=self.auth_headers(),
            )
            self.assertEqual(blocked.status_code, 429)
        finally:
            site.submit_limiter.limit = 6
            site.submit_limiter.hits.clear()

    def test_index_page_served(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("协议重登", resp.text)
        self.assertIn("卡密兑换", resp.text)
        # 顶部选项卡栏（不是入口卡片），且默认展开协议重登
        self.assertIn('class="tabs"', resp.text)
        self.assertIn('data-mode="reauth"', resp.text)
        self.assertIn('id="pane-reauth"', resp.text)
        self.assertNotIn('id="entry"', resp.text)
        self.assertIn("本站不接手机号", resp.text)

    def test_submit_rejects_bad_input(self):
        resp = self.client.post(
            "/api/submit",
            json={"text": "", "mode": "reauth"},
            headers=self.auth_headers(),
        )
        self.assertEqual(resp.status_code, 422)

    def test_unknown_job_is_404(self):
        resp = self.client.get("/api/job/does-not-exist")
        self.assertEqual(resp.status_code, 404)

    def test_download_before_finish_is_409(self):
        from app.jobs import Job

        job = Job(
            job_id="pending-job",
            created_at=0.0,
            mode="reauth",
            owner_ip="127.0.0.1",
        )
        with site.manager.lock:
            site.manager.jobs[job.job_id] = job
        resp = self.client.get("/api/job/pending-job/download/cpa")
        self.assertEqual(resp.status_code, 409)
        with site.manager.lock:
            site.manager.jobs.pop(job.job_id, None)

    def test_download_headers_survive_chinese_filename(self):
        """中文文件名必须百分号编码，否则 HTTP 头 latin-1 编码直接 500。"""
        from app.formats import collect_outputs
        from app.jobs import Job
        from tests.test_formats_and_totp import fake_session
        from app.formats import session_to_payloads

        outputs = collect_outputs(
            [
                {
                    "email": "a@b.com",
                    "plan_type": "plus",
                    "status": "ok",
                    "payloads": session_to_payloads(fake_session("a@b.com")),
                }
            ]
        )
        job = Job(
            job_id="finished-job",
            created_at=0.0,
            mode="reauth",
            owner_ip="127.0.0.1",
            outputs=outputs,
            finished_at=1.0,
        )
        with site.manager.lock:
            site.manager.jobs[job.job_id] = job
        try:
            for kind in ("sub2-merged", "cpa", "sub2-single", "cockpit"):
                resp = self.client.get(f"/api/job/finished-job/download/{kind}")
                self.assertEqual(resp.status_code, 200, kind)
                disposition = resp.headers["content-disposition"]
                self.assertIn("filename*=UTF-8''", disposition)
                self.assertTrue(
                    disposition.isascii(),
                    f"header must be ascii: {disposition}",
                )
            missing = self.client.get("/api/job/finished-job/download/nope")
            self.assertEqual(missing.status_code, 404)
        finally:
            with site.manager.lock:
                site.manager.jobs.pop(job.job_id, None)


if __name__ == "__main__":
    unittest.main()
