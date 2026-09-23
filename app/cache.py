"""本机会话缓存：同一个邮箱重登过，卡密兑换就能免登录秒出。"""

from __future__ import annotations

import threading
import time


class SessionCache:
    def __init__(self, ttl_seconds: int = 21600, *, max_items: int = 5000):
        self.ttl = max(300, int(ttl_seconds or 21600))
        self.max_items = max(50, int(max_items or 5000))
        self.lock = threading.Lock()
        self.items: dict[str, dict] = {}
        self.hits = 0
        self.misses = 0

    def get(self, email: str) -> dict | None:
        key = str(email or "").strip().lower()
        if not key:
            return None
        now = time.time()
        with self.lock:
            entry = self.items.get(key)
            if entry is None or entry["expires_at"] <= now:
                if entry is not None:
                    self.items.pop(key, None)
                self.misses += 1
                return None
            self.hits += 1
            return dict(entry)

    def put(
        self,
        email: str,
        *,
        payloads: dict,
        plan_type: str,
        account_id: str = "",
        expires_at: str = "",
    ) -> None:
        key = str(email or "").strip().lower()
        if not key:
            return
        with self.lock:
            self.items[key] = {
                "email": key,
                "payloads": payloads,
                "plan_type": plan_type,
                "account_id": account_id,
                "token_expires_at": expires_at,
                "cached_at": time.time(),
                "expires_at": time.time() + self.ttl,
            }
            if len(self.items) > self.max_items:
                oldest = sorted(
                    self.items,
                    key=lambda item: self.items[item]["cached_at"],
                )[: len(self.items) - self.max_items]
                for item in oldest:
                    self.items.pop(item, None)

    def prune(self) -> int:
        now = time.time()
        with self.lock:
            stale = [
                key
                for key, entry in self.items.items()
                if entry["expires_at"] <= now
            ]
            for key in stale:
                self.items.pop(key, None)
            return len(stale)

    def stats(self) -> dict:
        with self.lock:
            return {
                "items": len(self.items),
                "hits": self.hits,
                "misses": self.misses,
                "ttl_seconds": self.ttl,
            }
