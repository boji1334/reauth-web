"""解析「邮箱----密码----2fa」账号行。"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import parse_qs, unquote, urlparse

EMAIL_RE = re.compile(r"^[^\s@|]+@[^\s@|]+\.[^\s@|]+$")
FIELD_SPLIT_RE = re.compile(r"\s*-{2,}\s*|\s*\|\s*")
TOTP_BASE32_RE = re.compile(r"^[A-Z2-7]{8,128}$")


class AccountLineError(ValueError):
    """单行账号格式不合法。"""


@dataclass(frozen=True)
class AccountLine:
    email: str
    password: str
    totp_secret: str
    raw: str

    @property
    def canonical(self) -> str:
        return f"{self.email}----{self.password}----{self.totp_secret}"


def normalize_totp_secret(value: str) -> str:
    """接受 base32 密钥或 otpauth:// URI。"""
    text = str(value or "").strip()
    if not text:
        raise AccountLineError("缺少 2FA 密钥")
    if text.lower().startswith(("otpauth://", "otpauth:")):
        parsed = urlparse(text)
        query = parse_qs(parsed.query)
        secret = (query.get("secret") or [""])[0]
        text = unquote(secret).strip()
    normalized = re.sub(r"[\s\-_=]", "", text).upper()
    if not TOTP_BASE32_RE.fullmatch(normalized):
        raise AccountLineError("2FA 密钥不是有效的 base32")
    return normalized


def parse_account_line(raw: str) -> AccountLine:
    text = str(raw or "").strip()
    if not text:
        raise AccountLineError("空行")
    fields = [part.strip() for part in FIELD_SPLIT_RE.split(text)]
    fields = [part for part in fields if part]
    if len(fields) < 3:
        raise AccountLineError(
            "格式应为 邮箱----密码----2fa（用 ---- 或 | 分隔）"
        )
    email, password, secret = fields[0], fields[1], fields[2]
    # 第 4 列及以上会被忽略（例如带 sub2api json 直链的导出行）
    if not EMAIL_RE.fullmatch(email):
        raise AccountLineError(f"邮箱不合法：{email}")
    if not password:
        raise AccountLineError("缺少密码")
    return AccountLine(
        email=email.lower(),
        password=password,
        totp_secret=normalize_totp_secret(secret),
        raw=text,
    )


def parse_account_lines(
    raw: str,
    *,
    max_accounts: int = 0,
) -> tuple[list[AccountLine], list[str]]:
    """返回 (有效账号, 错误信息)。逐行独立校验，单行报错不影响其它行。"""
    lines = [line.strip() for line in str(raw or "").splitlines()]
    lines = [line for line in lines if line and not line.startswith("#")]
    if not lines:
        raise AccountLineError("请至少粘贴一行账号")
    seen: set[str] = set()
    accounts: list[AccountLine] = []
    errors: list[str] = []
    for index, line in enumerate(lines, start=1):
        try:
            account = parse_account_line(line)
        except AccountLineError as exc:
            errors.append(f"第 {index} 行：{exc}")
            continue
        if account.email in seen:
            errors.append(f"第 {index} 行：重复邮箱 {account.email}，已跳过")
            continue
        seen.add(account.email)
        accounts.append(account)
    if max_accounts > 0 and len(accounts) > max_accounts:
        raise AccountLineError(f"单次最多提交 {max_accounts} 个账号")
    if not accounts:
        raise AccountLineError("没有可处理的账号：" + "；".join(errors[:3]))
    return accounts, errors
