"""主站兑换通道：格式映射与文件名解析。"""

from __future__ import annotations

import json
import unittest

from app import upstream as upstream_module
from app.upstream import FORMAT_MAP, UpstreamClient, UpstreamError


class FakeSession:
    def __init__(self, *, status=200, payload=None, content=b"", headers=None):
        self.status = status
        self.status_code = status
        self.payload = payload
        self.content = content
        self.headers = headers or {}
        self.headers.update({"User-Agent": "x"})
        self.last_post = None

    def get(self, url, **kwargs):
        self.last_get = (url, kwargs)
        return self

    def post(self, url, **kwargs):
        self.last_post = (url, kwargs)
        return self

    def json(self):
        return self.payload


class UpstreamTests(unittest.TestCase):
    def test_format_map_matches_main_site(self):
        self.assertEqual(FORMAT_MAP["cpa"], "cpa")
        self.assertEqual(FORMAT_MAP["sub2-merged"], "sub2-merged")
        self.assertEqual(FORMAT_MAP["sub2-single"], "sub2")
        self.assertEqual(FORMAT_MAP["cockpit"], "cockpit")

    def test_not_configured(self):
        client = UpstreamClient("", "")
        self.assertFalse(client.configured)
        with self.assertRaises(UpstreamError):
            client.export("a@b.com----pw----ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", "cpa")

    def test_export_parses_utf8_filename(self):
        client = UpstreamClient("https://example.com", "key")
        client.session = FakeSession(
            content=b'{"accounts":[]}',
            headers={
                "Content-Type": "application/json",
                "Content-Disposition": "attachment; filename*=UTF-8''2-0923-0238-sub2%E5%90%88%E5%B9%B6.json",
            },
        )
        name, body, media = client.export("line", "sub2-merged")
        self.assertEqual(name, "2-0923-0238-sub2合并.json")
        self.assertEqual(body, b'{"accounts":[]}')
        self.assertEqual(media, "application/json")
        url, kwargs = client.session.last_post
        self.assertTrue(url.endswith("/api/admin/recovery-export"))
        sent = json.loads(kwargs["data"].decode("utf-8"))
        self.assertEqual(sent["output_format"], "sub2-merged")
        self.assertEqual(sent["account_mode"], "totp")
        self.assertEqual(kwargs["headers"]["X-CPA-Server-Key"], "key")

    def test_export_error_maps_to_upstream_error(self):
        client = UpstreamClient("https://example.com", "key")
        client.session = FakeSession(status=404, payload={"detail": "没有找到"})
        with self.assertRaises(UpstreamError) as ctx:
            client.export("line", "cpa")
        self.assertIn("404", str(ctx.exception))

    def test_lookup_filters_exact_email(self):
        client = UpstreamClient("https://example.com", "key")
        client.session = FakeSession(
            payload={
                "entries": [
                    {
                        "email": "other@icloud.com",
                        "download_available": True,
                        "status": "complete",
                    },
                    {
                        "email": "me@icloud.com",
                        "download_available": True,
                        "status": "complete",
                        "status_label": "已完成",
                    },
                ]
            }
        )
        info = client.lookup("me@icloud.com")
        self.assertTrue(info["available"])
        self.assertEqual(info["status_label"], "已完成")

    def test_lookup_reports_not_found(self):
        client = UpstreamClient("https://example.com", "key")
        client.session = FakeSession(payload={"entries": []})
        info = client.lookup("nobody@icloud.com")
        self.assertFalse(info["available"])
        self.assertEqual(info["status_label"], "未找到")
        self.assertIs(upstream_module.UpstreamError, UpstreamError)


if __name__ == "__main__":
    unittest.main()
