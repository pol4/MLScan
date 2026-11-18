#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v3/llm: unit-тесты GC кэша моделей (per-sha, LRU, защита активных/свежих)."""
from __future__ import annotations

import os
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "deploy", "v3", "llm"))

import model_cache_gc as gc  # noqa: E402

MB = 1 << 20
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64


def _entry(key, size, age_s, now, locked=False):
    return {"key": key, "path": "/x/" + key, "size": size, "last_used": now - age_s, "locked": locked}


class PlanEvictionTest(unittest.TestCase):
    def test_under_target_keeps_all(self):
        now = time.time()
        e = [_entry(SHA_A, MB, 10 * 3600, now)]
        self.assertEqual(gc.plan_eviction(e, 5 * MB, 1, 3600, now), [])

    def test_evicts_lru_until_target(self):
        now = time.time()
        e = [_entry(SHA_A, MB, 10 * 3600, now), _entry(SHA_B, 2 * MB, 9 * 3600, now),
             _entry(SHA_C, MB, 0, now)]
        out = gc.plan_eviction(e, 2 * MB, 1, 3600, now)
        self.assertEqual([v["key"] for v in out], [SHA_A, SHA_B])   # старейшие первыми

    def test_keeps_newest_k_and_recent_and_locked(self):
        now = time.time()
        e = [_entry(SHA_A, MB, 10 * 3600, now),           # oldest, evictable
             _entry(SHA_B, MB, 10 * 3600, now, locked=True),  # locked -> keep
             _entry(SHA_C, MB, 100, now),                 # fresh -> keep
             _entry(SHA_D, MB, 10 * 3600, now)]           # newest-максимум keep=1 -> не удалять как самый новый? см. ниже
        out = gc.plan_eviction(e, 0, 1, 3600, now)
        keys = {v["key"] for v in out}
        self.assertIn(SHA_A, keys)
        self.assertIn(SHA_D, keys)        # старые и не защищены -> удаляются
        self.assertNotIn(SHA_B, keys)     # locked -> не трогаем
        self.assertNotIn(SHA_C, keys)     # свежий И самый новый (keep=1) -> не трогаем


class ScanGcTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.cache = self.tmp.name

    def _mk(self, key, mb, age_s, ready=True, lock=False):
        d = os.path.join(self.cache, key)
        os.makedirs(os.path.join(d, "files"), exist_ok=True)
        with open(os.path.join(d, "files", "w.bin"), "wb") as fh:
            fh.write(b"x" * (mb * MB))
        ts = time.time() - age_s
        if ready:
            open(os.path.join(d, ".ready"), "w").close()
            open(os.path.join(d, ".used"), "w").close()
            for n in (".ready", ".used"):
                os.utime(os.path.join(d, n), (ts, ts))
            os.utime(d, (ts, ts))
        if lock:
            open(os.path.join(self.cache, key + ".lock"), "w").close()

    def test_scan_detects_entries_tmp_lock(self):
        self._mk(SHA_A, 1, 10 * 3600)
        os.makedirs(os.path.join(self.cache, SHA_B + ".tmp"), exist_ok=True)
        open(os.path.join(self.cache, SHA_C + ".lock"), "w").close()
        os.makedirs(os.path.join(self.cache, "not-a-sha"), exist_ok=True)
        st = gc.scan(self.cache)
        self.assertEqual([e["key"] for e in st["entries"]], [SHA_A])
        self.assertEqual([t["name"] for t in st["tmps"]], [SHA_B + ".tmp"])
        self.assertEqual([lk["name"] for lk in st["locks"]], [SHA_C + ".lock"])

    def test_gc_evicts_and_cleans(self):
        self._mk(SHA_A, 1, 10 * 3600)          # старейший
        self._mk(SHA_B, 2, 9 * 3600)           # старее остальных
        self._mk(SHA_C, 1, 0)                  # свежий (keep)
        self._mk(SHA_D, 1, 10 * 3600, lock=True)   # активный -> не трогать
        tmpd = os.path.join(self.cache, "e" * 64 + ".tmp")
        os.makedirs(tmpd, exist_ok=True)
        old = time.time() - 10 * 3600
        os.utime(tmpd, (old, old))
        r = gc.gc(self.cache, target_gb=2 * MB / (1 << 30), keep=1, min_idle_s=3600)
        self.assertIn(SHA_A, r["evicted"])
        self.assertIn(SHA_B, r["evicted"])
        self.assertNotIn(SHA_C, r["evicted"])
        self.assertNotIn(SHA_D, r["evicted"])
        self.assertFalse(os.path.exists(os.path.join(self.cache, SHA_A)))
        self.assertTrue(os.path.exists(os.path.join(self.cache, SHA_C)))
        self.assertTrue(os.path.exists(os.path.join(self.cache, SHA_D)))
        self.assertIn("e" * 64 + ".tmp", r["tmp_removed"])
        self.assertFalse(os.path.exists(tmpd))

    def test_dry_run_deletes_nothing(self):
        self._mk(SHA_A, 1, 10 * 3600)
        self._mk(SHA_B, 2, 9 * 3600)
        r = gc.gc(self.cache, target_gb=0, keep=0, min_idle_s=3600, dry_run=True)
        self.assertTrue(r["dry_run"])
        self.assertTrue(r["evicted"])
        self.assertTrue(os.path.exists(os.path.join(self.cache, SHA_A)))
        self.assertTrue(os.path.exists(os.path.join(self.cache, SHA_B)))


if __name__ == "__main__":
    unittest.main()
