"""引擎错误文案：手机号必须明确拒绝，不能含糊。"""

from __future__ import annotations

import unittest

from app.engine import _failure_reason, is_phone_required


class FailureReasonTests(unittest.TestCase):
    def test_phone_required_is_explicit(self):
        reason = _failure_reason(
            {"error": "phone_required", "page_type": "add-phone"}
        )
        self.assertIn("手机号", reason)
        self.assertIn("不提供手机号", reason)

    def test_add_phone_failed_is_explicit(self):
        self.assertIn(
            "不提供手机号",
            _failure_reason({"error": "add_phone_failed"}),
        )
        self.assertIn(
            "不提供手机号",
            _failure_reason({"error": "RuntimeError", "page_type": "add_phone"}),
        )

    def test_totp_hint(self):
        self.assertIn(
            "2FA",
            _failure_reason({"error": "mfa_totp_secret_required"}),
        )

    def test_generic_error_keeps_detail(self):
        reason = _failure_reason({"error": "oauth_callback_not_found"})
        self.assertIn("oauth_callback_not_found", reason)

    def test_phone_detection_helper(self):
        self.assertTrue(is_phone_required("phone_required"))
        self.assertTrue(is_phone_required("add_phone_requires_sms_client"))
        self.assertFalse(is_phone_required("mfa_totp_code_unavailable"))


if __name__ == "__main__":
    unittest.main()
