"""免登录转格式通道：sub2 文件 -> cpa / cockpit / sub2。"""

from __future__ import annotations

import base64
import json
import unittest

from app.convert import (
    ConvertError,
    convert_sub2_account,
    convert_sub2_text,
    extract_sub2_accounts,
)


def access_token(email: str = "a@b.com", plan: str = "plus") -> str:
    def seg(payload: dict) -> str:
        raw = json.dumps(payload).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    return ".".join(
        [
            seg({"alg": "none"}),
            seg(
                {
                    "exp": 4102444800,
                    "https://api.openai.com/auth": {
                        "chatgpt_account_id": "acct-1",
                        "chatgpt_user_id": "user-1",
                        "chatgpt_plan_type": plan,
                    },
                }
            ),
            "sig",
        ]
    )


def sub2_account(email: str = "a@b.com", plan: str = "plus") -> dict:
    return {
        "name": email,
        "platform": "openai",
        "type": "oauth",
        "concurrency": 10,
        "priority": 1,
        "credentials": {
            "access_token": access_token(email, plan),
            "refresh_token": "refresh-1",
            "id_token": "id-1",
            "chatgpt_account_id": "acct-1",
            "chatgpt_user_id": "user-1",
            "email": email,
            "expires_at": "2030-01-01T00:00:00Z",
            "expires_in": 3600,
            "plan_type": plan,
        },
        "extra": {"email": email, "last_refresh": "2026-09-23T00:00:00Z"},
    }


class ConvertTests(unittest.TestCase):
    def test_extracts_merged_document(self):
        text = json.dumps({"exported_at": "x", "proxies": [], "accounts": [sub2_account()]})
        self.assertEqual(len(extract_sub2_accounts(text)), 1)

    def test_extracts_single_account_object(self):
        self.assertEqual(len(extract_sub2_accounts(json.dumps(sub2_account()))), 1)

    def test_rejects_non_sub2_json(self):
        with self.assertRaises(ConvertError):
            extract_sub2_accounts('{"foo": 1}')
        with self.assertRaises(ConvertError):
            extract_sub2_accounts("not json")

    def test_rejects_account_without_access_token(self):
        broken = sub2_account()
        broken["credentials"].pop("access_token")
        with self.assertRaises(ConvertError):
            convert_sub2_account(broken)

    def test_maps_all_three_formats(self):
        item = convert_sub2_account(sub2_account("x@y.com", "team"))
        self.assertEqual(item["email"], "x@y.com")
        self.assertEqual(item["plan_type"], "team")
        self.assertEqual(item["cpa"]["type"], "codex")
        self.assertEqual(item["cpa"]["account_id"], "acct-1")
        self.assertEqual(item["cpa"]["plan_type"], "team")
        self.assertEqual(item["cpa"]["expired"], "2030-01-01T00:00:00Z")
        self.assertEqual(item["cpa"]["refresh_token"], "refresh-1")
        self.assertEqual(item["cockpit"]["account_id"], "acct-1")
        self.assertEqual(item["cockpit"]["email"], "x@y.com")
        self.assertEqual(
            item["sub2api"]["credentials"]["refresh_token"],
            "refresh-1",
        )
        self.assertEqual(item["sub2api"]["extra"]["source"], "sub2api_convert")

    def test_derives_expiry_from_jwt_when_missing(self):
        account = sub2_account()
        account["credentials"].pop("expires_at")
        item = convert_sub2_account(account)
        self.assertTrue(item["cpa"]["expired"].startswith("2100-01-01"))

    def test_convert_text_returns_every_account(self):
        text = json.dumps(
            {
                "accounts": [
                    sub2_account("a@b.com"),
                    sub2_account("c@d.com", "free"),
                ]
            }
        )
        items = convert_sub2_text(text)
        self.assertEqual([item["email"] for item in items], ["a@b.com", "c@d.com"])


if __name__ == "__main__":
    unittest.main()
