#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""P1: unit-тесты квот ingest (check_upload/check_part_size/throttle/fair_share)."""
from __future__ import annotations

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "deploy", "v3", "ingest"))

import quota as q  # noqa: E402


class UploadQuotaTest(unittest.TestCase):
    def test_unlimited_allows(self):
        qu = q.Quota(max_bytes_per_day=0, max_object_bytes=0)
        self.assertEqual(q.check_upload(qu, size=10 ** 12), (True, q.OK))

    def test_object_too_large(self):
        qu = q.Quota(max_object_bytes=100)
        self.assertEqual(q.check_upload(qu, size=101)[1], q.DENY_TOO_LARGE)
        self.assertEqual(q.check_upload(qu, size=100)[0], True)  # ровно лимит — ок

    def test_daily_quota(self):
        qu = q.Quota(max_bytes_per_day=1000)
        ok, code = q.check_upload(qu, size=200, used_bytes_today=900)
        self.assertFalse(ok); self.assertEqual(code, q.DENY_DAILY)
        self.assertTrue(q.check_upload(qu, size=100, used_bytes_today=900)[0])

    def test_concurrent_limit(self):
        qu = q.Quota(max_concurrent_uploads=2)
        self.assertEqual(q.check_upload(qu, size=10, concurrent_uploads=2)[1], q.DENY_CONCURRENT)
        self.assertTrue(q.check_upload(qu, size=10, concurrent_uploads=1)[0])

    def test_zero_or_negative_size(self):
        self.assertEqual(q.check_upload(q.Quota(), size=0)[1], q.DENY_TOO_LARGE)


class PartSizeTest(unittest.TestCase):
    def test_range(self):
        qu = q.Quota(min_part_size=5 * q.MiB, max_part_size=1024 * q.MiB)
        self.assertTrue(q.check_part_size(qu, 64 * q.MiB)[0])
        self.assertEqual(q.check_part_size(qu, 1 * q.MiB)[1], q.DENY_PART)
        self.assertEqual(q.check_part_size(qu, 2048 * q.MiB)[1], q.DENY_PART)

    def test_1gib_allowed(self):
        qu = q.Quota()
        self.assertTrue(q.check_part_size(qu, 1024 * q.MiB)[0])


class ThrottleTest(unittest.TestCase):
    def test_levels(self):
        qu = q.Quota(max_bytes_per_day=1000)
        self.assertEqual(q.throttle_decision(qu, 500), "ok")
        self.assertEqual(q.throttle_decision(qu, 900), "throttle")
        self.assertEqual(q.throttle_decision(qu, 1000), "deny")
        self.assertEqual(q.throttle_decision(q.Quota(), 10 ** 12), "ok")


class FairShareTest(unittest.TestCase):
    def test_equal(self):
        sh = q.fair_share(["a", "b", "c", "d"])
        self.assertAlmostEqual(sum(sh.values()), 1.0, places=5)
        self.assertAlmostEqual(sh["a"], 0.25, places=5)

    def test_weighted(self):
        sh = q.fair_share(["a", "b"], {"a": 3.0, "b": 1.0})
        self.assertAlmostEqual(sh["a"], 0.75, places=5)
        self.assertAlmostEqual(sh["b"], 0.25, places=5)

    def test_empty(self):
        self.assertEqual(q.fair_share([]), {})


if __name__ == "__main__":
    unittest.main(verbosity=2)
