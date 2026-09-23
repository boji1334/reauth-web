"""卡密兑换 = 纯兑换站：只查主站库存取成品，绝不登录。"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import json

from app import jobs as jobs_module
from app.config import Settings
from app.jobs import MODE_REDEEM, JobManager
from app.parsing import parse_account_line

SECRET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def make_settings() -> Settings:
    settings = Settings(data_dir=Path(tempfile.mkdtemp()))
    settings.auth_min_interval_seconds = 0
    settings.concurrency = 1
    return settings


def fake_payloads(email: str) -> dict:
    return {
        "cpa": {"type": "codex", "email": email, "access_token": "a", "refresh_token": "r"},
        "cockpit": {"type": "codex", "email": email, "access_token": "a"},
        "sub2api": {
            "exported_at": "2026-09-23T00:00:00Z",
            "proxies": [],
            "accounts": [
                {
                    "name": email,
                    "platform": "openai",
                    "type": "oauth",
                    "credentials": {
                        "access_token": "a",
                        "refresh_token": "r",
                        "id_token": "i",
                        "email": email,
                        "plan_type": "free",
                    },
                }
            ],
        },
    }


class FakeResponse:
    def __init__(self, status_code=200, payload=None, content=b"", headers=None):
        self.status_code = status_code
        self._payload = payload
        self.content = content
        self.headers = headers or {}

    def json(self):
        return self._payload


class FakeUpstream:
    def __init__(self, *, available=True):
        self.available = available
        self.export_calls: list[str] = []
        self.lookup_calls: list[str] = []
        self.configured = True

    def lookup(self, email):
        self.lookup_calls.append(email)
        return {
            "ok": True,
            "available": self.available,
            "status": "complete" if self.available else "error",
            "status_label": "已完成" if self.available else "失败",
        }

    def export(self, account_text, output_format):
        self.export_calls.append(output_format)
        body = json.dumps(
            {"format": output_format, "lines": len(account_text.splitlines())}
        ).encode("utf-8")
        return f"{output_format}-out.json", body, "application/json"


class RedeemPathTests(unittest.TestCase):
    def setUp(self):
        self.settings = make_settings()
        self.manager = JobManager(self.settings)
        self.fake = FakeUpstream()
        self.manager.upstream = self.fake
        self.called = {"login": 0}

        def guard(*_args, **_kwargs):
            self.called["login"] += 1
            raise AssertionError("命中缓存时不应该调用协议登录")

        self._original = jobs_module.reauth_account
        jobs_module.reauth_account = guard

    def tearDown(self):
        jobs_module.reauth_account = self._original
        self.manager.executor.shutdown(wait=False, cancel_futures=True)

    def test_redeem_never_logs_in_and_fetches_from_upstream(self):
        account = parse_account_line(f"stock@icloud.com----pw----{SECRET}")
        job = self.manager.create_job(
            [account],
            mode=MODE_REDEEM,
            owner_ip="127.0.0.1",
        )
        for _ in range(200):
            if job.finished_at:
                break
            import time

            time.sleep(0.05)
        self.assertTrue(job.finished_at)
        state = job.accounts[0]
        self.assertEqual(state.status, "done")
        self.assertEqual(self.called["login"], 0)
        self.assertEqual(self.fake.lookup_calls, [account.email])
        self.assertEqual(job.outputs["source"], "upstream")
        self.assertEqual(job.outputs["count"], 1)
        # 4 个轻量步骤全部完成
        self.assertEqual(
            [step.status for step in state.steps],
            ["done", "done", "done", "done"],
        )
        # 下载时按格式向主站取一次，并缓存
        name, body, media = self.manager.fetch_redeem_output(job, "sub2-single")
        self.assertEqual(name, "sub2-single-out.json")
        self.assertIn(b"sub2-single", body)
        self.manager.fetch_redeem_output(job, "sub2-single")
        self.assertEqual(self.fake.export_calls, ["sub2-single"])
        self.assertEqual(media, "application/json")

    def test_redeem_reports_missing_stock(self):
        self.fake.available = False
        account = parse_account_line(f"missing@icloud.com----pw----{SECRET}")
        job = self.manager.create_job(
            [account],
            mode=MODE_REDEEM,
            owner_ip="127.0.0.1",
        )
        for _ in range(200):
            if job.finished_at:
                break
            import time

            time.sleep(0.05)
        self.assertEqual(self.called["login"], 0)
        state = job.accounts[0]
        self.assertEqual(state.status, "error")
        self.assertIn("主站没有", state.message)
        self.assertEqual(job.outputs["count"], 0)
        self.assertEqual(
            [step.status for step in state.steps],
            ["done", "error", "pending", "pending"],
        )


if __name__ == "__main__":
    unittest.main()
