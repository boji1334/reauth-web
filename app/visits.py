"""匿名访客统计：今日访客 / 今日访问 / 近 10 分钟在线 + 最近 7 天趋势。

- 只保存 visitor_id 的 sha256 前 16 位，不存 IP、不存 UA、不写 cookie
- 内存为主，按天落一份 JSON 到 /data，容器重启不丢当天数字
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

SAVE_INTERVAL_SECONDS = 20
MAX_VISITORS_PER_DAY = 50000
MAX_MINUTE_BUCKETS = 24 * 60 + 120


class VisitTracker:
    def __init__(
        self,
        data_dir: Path,
        *,
        timezone_name: str = "Asia/Shanghai",
        retention_days: int = 14,
    ):
        self.path = Path(data_dir) / "visits.json"
        self.retention_days = max(2, int(retention_days or 14))
        try:
            self.tz = ZoneInfo(timezone_name)
        except Exception:  # noqa: BLE001 - 时区库缺失时退化为 UTC+8
            self.tz = None
        self.lock = threading.Lock()
        self.days: dict[str, dict] = {}
        self.salt = ""
        self._last_save = 0.0
        self._load()

    # ---------------- 基础 ----------------
    def _now(self) -> datetime:
        if self.tz is not None:
            return datetime.now(self.tz)
        return datetime.utcnow() + timedelta(hours=8)

    def _digest(self, visitor_id: str) -> str:
        return hashlib.sha256(
            f"{self.salt}|{visitor_id}".encode("utf-8")
        ).hexdigest()[:16]

    def _load(self) -> None:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self.salt = hashlib.sha256(str(time.time()).encode()).hexdigest()[:16]
            return
        if not isinstance(raw, dict):
            return
        self.salt = str(raw.get("salt") or "") or hashlib.sha256(
            str(time.time()).encode()
        ).hexdigest()[:16]
        days = raw.get("days")
        if isinstance(days, dict):
            for key, value in days.items():
                if not isinstance(value, dict):
                    continue
                self.days[str(key)] = {
                    "visits": int(value.get("visits") or 0),
                    "visitors": set(value.get("visitors") or []),
                    "minutes": {
                        str(minute): set(ids or [])
                        for minute, ids in (value.get("minutes") or {}).items()
                    },
                }

    def _save(self) -> None:
        payload = {
            "salt": self.salt,
            "days": {
                key: {
                    "visits": value["visits"],
                    "visitors": sorted(value["visitors"]),
                    "minutes": {
                        minute: sorted(ids)
                        for minute, ids in value["minutes"].items()
                    },
                }
                for key, value in self.days.items()
            },
        }
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(
                json.dumps(payload, ensure_ascii=False),
                encoding="utf-8",
            )
            tmp.replace(self.path)
        except OSError:
            pass

    def _prune(self, today: datetime) -> None:
        keep = {
            (today - timedelta(days=offset)).strftime("%Y-%m-%d")
            for offset in range(self.retention_days)
        }
        for key in list(self.days):
            if key not in keep:
                self.days.pop(key, None)
        for value in self.days.values():
            if len(value["minutes"]) > MAX_MINUTE_BUCKETS:
                for minute in sorted(value["minutes"])[:-MAX_MINUTE_BUCKETS]:
                    value["minutes"].pop(minute, None)

    # ---------------- 记录 ----------------
    def record(self, visitor_id: str, *, now: float | None = None) -> dict:
        stamp = self._now() if now is None else datetime.fromtimestamp(
            float(now),
            self.tz,
        )
        day_key = stamp.strftime("%Y-%m-%d")
        minute_key = stamp.strftime("%H:%M")
        digest = self._digest(str(visitor_id or "") or "anonymous")
        with self.lock:
            entry = self.days.setdefault(
                day_key,
                {"visits": 0, "visitors": set(), "minutes": {}},
            )
            if len(entry["visitors"]) < MAX_VISITORS_PER_DAY:
                entry["visitors"].add(digest)
            entry["visits"] += 1
            entry["minutes"].setdefault(minute_key, set()).add(digest)
            self._prune(stamp)
            if time.time() - self._last_save >= SAVE_INTERVAL_SECONDS:
                self._save()
                self._last_save = time.time()
            return self._snapshot_locked(stamp)

    # ---------------- 读取 ----------------
    def _snapshot_locked(self, now: datetime) -> dict:
        day_key = now.strftime("%Y-%m-%d")
        entry = self.days.get(day_key) or {
            "visits": 0,
            "visitors": set(),
            "minutes": {},
        }
        online: set[str] = set()
        for offset in range(10):
            minute_key = (now - timedelta(minutes=offset)).strftime("%H:%M")
            online |= entry["minutes"].get(minute_key, set())
        days = []
        for offset in range(6, -1, -1):
            key = (now - timedelta(days=offset)).strftime("%Y-%m-%d")
            value = self.days.get(key) or {
                "visits": 0,
                "visitors": set(),
            }
            days.append(
                {
                    "date": key,
                    "visitors": len(value["visitors"]),
                    "visits": int(value["visits"]),
                }
            )
        return {
            "ok": True,
            "server_date": day_key,
            "today_visitors": len(entry["visitors"]),
            "today_visits": int(entry["visits"]),
            "online": len(online),
            "days": days,
        }

    def snapshot(self) -> dict:
        with self.lock:
            return self._snapshot_locked(self._now())
