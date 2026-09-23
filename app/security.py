"""防滥用：会话令牌（HMAC 绑定 IP/UA）+ 多层限流。

说明：浏览器一定会拿到前端代码，所以这里的目标不是「让人看不到页面」，
而是：① 不泄露任何密钥与后端逻辑 ② 挡住脚本/爬虫批量刷接口 ③ 挡住绕过
Cloudflare 直连源站（见 Caddyfile 的只允许 CF 回源）。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
from collections import defaultdict, deque
from pathlib import Path

TOKEN_TTL_SECONDS = 1800


def _digest(value: str) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()[:16]


class SessionTokens:
    """绑定 IP + UA 指纹的短时令牌；页面自动携带，脚本要过就得先过浏览器。"""

    def __init__(self, data_dir: Path, secret: str = ""):
        self.secret = str(secret or "").strip()
        if not self.secret:
            self.secret = self._load_or_create(data_dir)

    @staticmethod
    def _load_or_create(data_dir: Path) -> str:
        path = Path(data_dir) / "session-secret"
        try:
            existing = path.read_text(encoding="utf-8").strip()
            if existing:
                return existing
        except OSError:
            pass
        value = secrets.token_urlsafe(32)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(value, encoding="utf-8")
        except OSError:
            pass
        return value

    def _sign(self, payload: str) -> str:
        return hmac.new(
            self.secret.encode("utf-8"),
            payload.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()

    def issue(
        self,
        *,
        ip: str = "",
        user_agent: str = "",
        ttl: int = TOKEN_TTL_SECONDS,
        now: float | None = None,
    ) -> tuple[str, int]:
        issued = int(now if now is not None else time.time())
        ttl = max(60, int(ttl or TOKEN_TTL_SECONDS))
        body = {
            "ip": _digest(ip),
            "ua": _digest(user_agent),
            "iat": issued,
            "exp": issued + ttl,
        }
        raw = base64.urlsafe_b64encode(
            json.dumps(body, separators=(",", ":")).encode("utf-8")
        ).decode("ascii").rstrip("=")
        return f"{raw}.{self._sign(raw)}", ttl

    def verify(
        self,
        token: str,
        *,
        ip: str = "",
        user_agent: str = "",
        now: float | None = None,
    ) -> bool:
        raw, _, signature = str(token or "").strip().partition(".")
        if not raw or not signature:
            return False
        if not hmac.compare_digest(signature, self._sign(raw)):
            return False
        try:
            padded = raw + "=" * (-len(raw) % 4)
            body = json.loads(
                base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
            )
        except (ValueError, UnicodeDecodeError):
            return False
        if body.get("exp", 0) <= int(now if now is not None else time.time()):
            return False
        if body.get("ip") != _digest(ip):
            return False
        if body.get("ua") != _digest(user_agent):
            return False
        return True


class RateLimiter:
    """滑动窗口限流：每个 key 一份，外加一个全局额度。"""

    def __init__(self, limit: int, window_seconds: float = 60.0):
        self.limit = max(1, int(limit))
        self.window = max(1.0, float(window_seconds))
        self.lock = threading.Lock()
        self.hits: dict[str, deque[float]] = defaultdict(deque)
        self._last_gc = time.time()

    def allow(self, key: str, *, now: float | None = None) -> tuple[bool, int]:
        stamp = float(now if now is not None else time.time())
        with self.lock:
            bucket = self.hits[key]
            cutoff = stamp - self.window
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= self.limit:
                retry = max(1, int(self.window - (stamp - bucket[0])) + 1)
                return False, retry
            bucket.append(stamp)
            if stamp - self._last_gc > 300:
                for item in list(self.hits):
                    keep = self.hits[item]
                    while keep and keep[0] <= cutoff:
                        keep.popleft()
                    if not keep:
                        self.hits.pop(item, None)
                self._last_gc = stamp
            return True, 0

    def stats(self) -> dict:
        with self.lock:
            return {"keys": len(self.hits), "limit": self.limit, "window": self.window}
