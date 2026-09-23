"""账号行解析：邮箱----密码----2fa（兼容 | 分隔与多余列）。"""

from __future__ import annotations

import unittest

from app.parsing import (
    AccountLineError,
    normalize_totp_secret,
    parse_account_line,
    parse_account_lines,
)

SECRET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


class ParseAccountLineTests(unittest.TestCase):
    def test_parses_dash_separated_line(self):
        line = parse_account_line(f"User@iCloud.com----pw-1qaz----{SECRET}")
        self.assertEqual(line.email, "user@icloud.com")
        self.assertEqual(line.password, "pw-1qaz")
        self.assertEqual(line.totp_secret, SECRET)

    def test_parses_pipe_separated_line(self):
        line = parse_account_line(f"a@b.com|pw|{SECRET}")
        self.assertEqual(line.canonical, f"a@b.com----pw----{SECRET}")

    def test_ignores_extra_trailing_columns(self):
        line = parse_account_line(
            f"a@b.com----pw----{SECRET}----https://example.com/x.json"
        )
        self.assertEqual(line.totp_secret, SECRET)

    def test_normalizes_otpauth_uri(self):
        secret = normalize_totp_secret(
            f"otpauth://totp/ChatGPT:a@b.com?secret={SECRET}&issuer=OpenAI"
        )
        self.assertEqual(secret, SECRET)

    def test_rejects_two_columns(self):
        with self.assertRaises(AccountLineError):
            parse_account_line("a@b.com----pw")

    def test_rejects_bad_secret(self):
        with self.assertRaises(AccountLineError):
            parse_account_line("a@b.com----pw----not-a-secret!!")

    def test_dedupes_and_reports_line_errors(self):
        accounts, errors = parse_account_lines(
            "\n".join(
                [
                    f"a@b.com----pw----{SECRET}",
                    f"a@b.com----pw----{SECRET}",
                    "坏行",
                    f"c@d.com----pw2----{SECRET}",
                ]
            )
        )
        self.assertEqual([item.email for item in accounts], ["a@b.com", "c@d.com"])
        self.assertEqual(len(errors), 2)

    def test_enforces_max_accounts(self):
        with self.assertRaises(AccountLineError):
            parse_account_lines(
                "\n".join(
                    f"u{i}@b.com----pw----{SECRET}" for i in range(5)
                ),
                max_accounts=3,
            )


if __name__ == "__main__":
    unittest.main()
