#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""P5: unit-тесты selector срезов для сэмплированной динамики."""
from __future__ import annotations

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "deploy", "v3", "analysis"))

import slice_selector  # noqa: E402


class SliceSelectorTest(unittest.TestCase):
    def test_small_file_full(self):
        r = slice_selector.select_slices(1024, max_slice_bytes=1024, max_slices=4)
        self.assertEqual(len(r["slices"]), 1)
        self.assertEqual(r["slices"][0]["kind"], "full")
        self.assertEqual(r["coverage_ratio"], 1.0)

    def test_budget_respected(self):
        total = 1024 ** 3  # 1 ГиБ
        r = slice_selector.select_slices(total, max_slice_bytes=16 * 1024 ** 2, max_slices=6)
        self.assertLessEqual(len(r["slices"]), 6)
        self.assertTrue(all(s["length"] <= 16 * 1024 ** 2 for s in r["slices"]))
        self.assertLess(r["covered_bytes"], total)
        self.assertGreater(r["coverage_ratio"], 0.0)
        # границы внутри объекта
        for s in r["slices"]:
            self.assertGreaterEqual(s["offset"], 0)
            self.assertLessEqual(s["offset"] + s["length"], total)

    def test_head_tail_present(self):
        r = slice_selector.select_slices(1024 ** 3, max_slice_bytes=8 * 1024 ** 2, max_slices=5)
        kinds = {s["kind"] for s in r["slices"]}
        self.assertIn("head", kinds); self.assertIn("tail", kinds)

    def test_deterministic(self):
        a = slice_selector.select_slices(1024 ** 3, seed=42)
        b = slice_selector.select_slices(1024 ** 3, seed=42)
        self.assertEqual(a["slices"], b["slices"])
        c = slice_selector.select_slices(1024 ** 3, seed=7)
        self.assertNotEqual(a["slices"], c["slices"])

    def test_coverage_grows_with_budget(self):
        total = 10 ** 10
        small = slice_selector.select_slices(total, max_slice_bytes=8 * 1024 ** 2, max_slices=3)
        big = slice_selector.select_slices(total, max_slice_bytes=8 * 1024 ** 2, max_slices=8)
        self.assertLess(small["coverage_ratio"], big["coverage_ratio"])

    def test_zero(self):
        self.assertEqual(slice_selector.select_slices(0)["slices"], [])

    def test_members_for_dynamic_priority_and_budget(self):
        members = [
            {"name": "z.txt", "uncompressed": 100},
            {"name": "b.pkl", "uncompressed": 500},
            {"name": "huge.pkl", "uncompressed": 10 ** 12},
            {"name": "skip.bin", "uncompressed": 10, "skip_reason": "bomb"},
        ]
        sel = slice_selector.select_members_for_dynamic(members, max_member_bytes=1000, max_count=5)
        names = [m["name"] for m in sel]
        self.assertEqual(names[0], "b.pkl")          # приоритетный формат первым
        self.assertIn("z.txt", names)
        self.assertNotIn("huge.pkl", names)          # превышает бюджет
        self.assertNotIn("skip.bin", names)          # пропущенный член не берём


if __name__ == "__main__":
    unittest.main(verbosity=2)
