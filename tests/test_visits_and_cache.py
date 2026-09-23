"""访客统计与session缓存。"""

from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path

from app.cache import SessionCache
from app.visits import VisitTracker


class VisitTrackerTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.tracker = VisitTracker(self.dir)

    def test_counts_unique_visitors_and_visits(self):
        first = self.tracker.record("visitor-a")
        self.assertEqual(first["today_visitors"], 1)
        self.assertEqual(first["today_visits"], 1)
        again = self.tracker.record("visitor-a")
        self.assertEqual(again["today_visitors"], 1)
        self.assertEqual(again["today_visits"], 2)
        other = self.tracker.record("visitor-b")
        self.assertEqual(other["today_visitors"], 2)
        self.assertEqual(other["today_visits"], 3)

    def test_online_window_and_seven_days(self):
        self.tracker.record("visitor-a")
        snapshot = self.tracker.snapshot()
        self.assertEqual(snapshot["online"], 1)
        self.assertEqual(len(snapshot["days"]), 7)
        self.assertEqual(snapshot["days"][-1]["visitors"], 1)

    def test_persists_and_reloads(self):
        self.tracker.record("visitor-a")
        self.tracker._save()  # noqa: SLF001 - 测试里强制落盘
        reloaded = VisitTracker(self.dir)
        self.assertEqual(reloaded.snapshot()["today_visitors"], 1)

    def test_does_not_store_raw_visitor_id(self):
        self.tracker.record("secret-visitor-id")
        self.tracker._save()  # noqa: SLF001
        raw = (self.dir / "visits.json").read_text(encoding="utf-8")
        self.assertNotIn("secret-visitor-id", raw)


class SessionCacheTests(unittest.TestCase):
    def test_hit_and_miss(self):
        cache = SessionCache(600)
        self.assertIsNone(cache.get("a@b.com"))
        cache.put(
            "a@b.com",
            payloads={"sub2api": {"accounts": [{"name": "a"}]}},
            plan_type="plus",
        )
        entry = cache.get("A@B.COM")
        self.assertIsNotNone(entry)
        self.assertEqual(entry["plan_type"], "plus")
        stats = cache.stats()
        self.assertEqual(stats["hits"], 1)
        self.assertEqual(stats["misses"], 1)

    def test_expires(self):
        cache = SessionCache(600)
        cache.put("a@b.com", payloads={"sub2api": {"accounts": [{}]}}, plan_type="free")
        with cache.lock:
            cache.items["a@b.com"]["expires_at"] = time.time() - 1
        self.assertIsNone(cache.get("a@b.com"))
        self.assertEqual(cache.prune(), 0)

    def test_prunes_expired_entries(self):
        cache = SessionCache(600)
        cache.put("a@b.com", payloads={"sub2api": {"accounts": [{}]}}, plan_type="free")
        with cache.lock:
            cache.items["a@b.com"]["expires_at"] = time.time() - 1
        self.assertEqual(cache.prune(), 1)


if __name__ == "__main__":
    unittest.main()
