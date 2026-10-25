#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""P9: unit-тесты миграции v2→v3 (dst_key, план, реконсиляция, готовность)."""
from __future__ import annotations

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "deploy", "v3", "migration"))
sys.path.insert(0, os.path.join(ROOT, "deploy", "v3", "data"))

import migrate  # noqa: E402

SHA = "ab" * 32


class MigrationTest(unittest.TestCase):
    def test_dst_key_pool(self):
        self.assertEqual(migrate.dst_key(SHA), f"objects/ab/ab/{SHA}")
        self.assertNotIn("tenant", migrate.dst_key(SHA, "t1"))

    def test_plan_from_v2_keys(self):
        rows = [
            {"s3_key": f"sha256/model.bin", "sha256": SHA, "tenant": "a", "size": 10},
            {"key": f"tenant/b/{SHA}/model.bin", "sha256": SHA, "tenant": "b", "size": 10},
            {"s3_key": "x", "sha256": ""},                      # пропускается
        ]
        plan = migrate.plan_object_migration(rows)
        self.assertEqual(len(plan), 2)
        self.assertTrue(all(p["dst_key"] == f"objects/ab/ab/{SHA}" for p in plan))
        self.assertEqual({p["tenant"] for p in plan}, {"a", "b"})

    def test_reconcile(self):
        r = migrate.reconcile([SHA, "cd" * 32], [SHA])
        self.assertFalse(r["ok"])
        self.assertEqual(r["missing_in_v3"], ["cd" * 32])
        self.assertTrue(migrate.reconcile([SHA], [SHA])["ok"])

    def test_readiness(self):
        ok, reasons = migrate.readiness({"objects_migrated": True, "refs_ok": True,
                                         "evidence_verified": True, "no_v2_writes": True, "slo_ok": True})
        self.assertTrue(ok); self.assertEqual(reasons, [])
        ok2, reasons2 = migrate.readiness({"objects_migrated": True, "refs_ok": False})
        self.assertFalse(ok2); self.assertIn("refs_ok", reasons2); self.assertIn("no_v2_writes", reasons2)
        ok3, reasons3 = migrate.readiness({"objects_migrated": True, "refs_ok": True,
                                           "evidence_verified": True, "no_v2_writes": True, "slo_ok": False})
        self.assertFalse(ok3); self.assertIn("slo_not_met", reasons3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
