"""本地生成 2FA 动态码（RFC 6238），不落盘、不打印密钥。"""

from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time


def _decode_secret(secret: str) -> bytes:
    normalized = str(secret or "").strip().upper().replace(" ", "")
    padding = "=" * (-len(normalized) % 8)
    try:
        return base64.b32decode(normalized + padding, casefold=True)
    except Exception as exc:  # noqa: BLE001 - 统一转成可读错误
        raise ValueError("2FA 密钥解析失败") from exc


def totp_code(
    secret: str,
    *,
    at_time: float | None = None,
    period: int = 30,
    digits: int = 6,
) -> tuple[str, int]:
    """返回 (动态码, 距离下一次刷新还剩多少秒)。"""
    key = _decode_secret(secret)
    now = float(at_time if at_time is not None else time.time())
    step = max(1, int(period or 30))
    counter = int(now // step)
    digest = hmac.new(
        key,
        struct.pack(">Q", counter),
        hashlib.sha1,
    ).digest()
    offset = digest[-1] & 0x0F
    truncated = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    code = str(truncated % (10 ** int(digits))).zfill(int(digits))
    remaining = step - int(now % step)
    return code, remaining


class TotpMfaClient:
    """给协议客户端用的 2FA 提供者，接口与生产环境一致。"""

    def __init__(self, secret: str, *, period: int = 30, max_attempts: int = 3):
        self.secret = str(secret or "").strip()
        self.period = max(10, int(period or 30))
        self.max_attempts = max(1, int(max_attempts or 3))

    def get_mfa_code(self, timeout: float = 90, exclude_codes=None):
        excluded = {
            str(value).strip()
            for value in (exclude_codes or set())
            if str(value).strip()
        }
        deadline = time.monotonic() + max(5.0, float(timeout or 90))
        while time.monotonic() < deadline:
            code, remaining = totp_code(self.secret, period=self.period)
            if code not in excluded and remaining > 4:
                return code
            time.sleep(min(0.5, max(0.05, deadline - time.monotonic())))
        return None
