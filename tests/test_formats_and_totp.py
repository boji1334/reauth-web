"""2FA 动态码 + 四种交付文件组装。"""

from __future__ import annotations

import json
import unittest
import zipfile
import io

from app.formats import (
    build_zip,
    collect_outputs,
    output_bundle,
    safe_name,
    session_to_payloads,
)
from app.totp import TotpMfaClient, totp_code


def fake_session(email: str = "user@icloud.com") -> dict:
    """构造一个最小可用 session（JWT 用 base64 明文段拼出来）。"""
    import base64

    def seg(payload: dict) -> str:
        raw = json.dumps(payload).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    access = ".".join(
        [
            seg({"alg": "RS256", "typ": "JWT"}),
            seg(
                {
                    "exp": 4102444800,
                    "email": email,
                    "https://api.openai.com/auth": {
                        "chatgpt_account_id": "acct-123",
                        "chatgpt_user_id": "user-123",
                        "chatgpt_plan_type": "plus",
                    },
                }
            ),
            "sig",
        ]
    )
    return {
        "accessToken": access,
        "refreshToken": "refresh-token",
        "idToken": "id-token",
        "email": email,
    }


class TotpTests(unittest.TestCase):
    def test_matches_rfc6238_vector(self):
        # RFC 6238 附录 B：secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ, T=59s -> 287082
        code, _remaining = totp_code(
            "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
            at_time=59,
        )
        self.assertEqual(code, "287082")

    def test_client_returns_six_digits(self):
        client = TotpMfaClient("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        code = client.get_mfa_code(timeout=10)
        self.assertIsNotNone(code)
        self.assertRegex(code, r"^\d{6}$")


class FormatsTests(unittest.TestCase):
    def test_session_builds_all_three_payloads(self):
        session = fake_session()
        payloads = session_to_payloads(session)
        self.assertEqual(payloads["item"]["plan_type"], "plus")
        self.assertEqual(
            payloads["sub2api"]["accounts"][0]["credentials"]["access_token"],
            session["accessToken"],
        )
        self.assertEqual(
            payloads["sub2api"]["accounts"][0]["credentials"]["refresh_token"],
            "refresh-token",
        )
        self.assertEqual(payloads["cpa"]["type"], "codex")
        self.assertEqual(payloads["cpa"]["account_id"], "acct-123")
        self.assertEqual(payloads["cockpit"]["email"], "user@icloud.com")

    def test_collect_outputs_builds_four_deliverables(self):
        results = [
            {
                "email": "a@b.com",
                "plan_type": "plus",
                "status": "ok",
                "payloads": session_to_payloads(fake_session("a@b.com")),
            },
            {
                "email": "c@d.com",
                "plan_type": "free",
                "status": "ok",
                "payloads": session_to_payloads(fake_session("c@d.com")),
            },
            {"email": "x@y.com", "status": "error", "payloads": {}},
        ]
        outputs = collect_outputs(results)
        self.assertEqual(outputs["count"], 2)
        self.assertEqual(len(outputs["sub2-merged"]["accounts"]), 2)
        self.assertEqual(len(outputs["cpa"]), 2)
        self.assertEqual(len(outputs["sub2-single"]), 2)
        self.assertEqual(len(outputs["cockpit"]), 2)

    def test_output_bundle_shapes(self):
        results = [
            {
                "email": "a@b.com",
                "plan_type": "plus",
                "status": "ok",
                "payloads": session_to_payloads(fake_session("a@b.com")),
            }
        ]
        outputs = collect_outputs(results)
        name, body, media = output_bundle(outputs, "sub2-merged")
        self.assertTrue(name.endswith("-sub2合并.json"))
        self.assertEqual(media, "application/json")
        self.assertEqual(len(json.loads(body)["accounts"]), 1)

        name, body, media = output_bundle(outputs, "cpa")
        self.assertEqual(name, "a@b.com.json")
        self.assertEqual(media, "application/json")
        self.assertEqual(json.loads(body)["account_id"], "acct-123")

        two = collect_outputs(
            results
            + [
                {
                    "email": "c@d.com",
                    "plan_type": "free",
                    "status": "ok",
                    "payloads": session_to_payloads(fake_session("c@d.com")),
                }
            ]
        )
        name, body, media = output_bundle(two, "sub2-single")
        self.assertTrue(name.endswith("-sub2单独.zip"))
        self.assertEqual(media, "application/zip")
        with zipfile.ZipFile(io.BytesIO(body)) as archive:
            self.assertEqual(
                sorted(archive.namelist()),
                ["a@b.com.json", "c@d.com.json"],
            )

    def test_output_bundle_raises_without_success(self):
        outputs = collect_outputs(
            [{"email": "x@y.com", "status": "error", "payloads": {}}]
        )
        with self.assertRaises(KeyError):
            output_bundle(outputs, "cpa")

    def test_safe_name_strips_path_characters(self):
        self.assertEqual(safe_name("a/b:c@d.com"), "a_b_c@d.com")
        self.assertEqual(safe_name(""), "account")


if __name__ == "__main__":
    unittest.main()
