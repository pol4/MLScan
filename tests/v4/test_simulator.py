#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v4: unit-тесты симулятора/бэктеста политики (матрица ошибок, sweep)."""
from __future__ import annotations

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "deploy", "v4"))

import scoring.policy as pol            # noqa: E402
import scoring.simulator as sim         # noqa: E402


class SimulateTest(unittest.TestCase):
    def test_confusion(self):
        cases = [
            {"id": "safe1", "profile": "llm", "results": {"safety_fail": 0, "pass_rate": 1.0},
             "expected": "Safe"},
            {"id": "unsafe1", "profile": "llm", "results": {"safety_fail": 2, "pass_rate": 0.9},
             "expected": "Needs review"},
            # эталон unsafe, но политика скажет Safe -> FN (пропуск)
            {"id": "missed1", "profile": "llm", "results": {"safety_fail": 0, "pass_rate": 1.0},
             "label": "unsafe"},
        ]
        out = sim.simulate(pol.DEFAULT_POLICY, cases, default_profile="llm")
        s = out["summary"]
        self.assertEqual(s["tp"], 1)
        self.assertEqual(s["tn"], 1)
        self.assertEqual(s["fn"], 1)
        self.assertEqual(s["fp"], 0)
        self.assertEqual([m["id"] for m in out["missed"]], ["missed1"])

    def test_inconclusive_counted(self):
        cases = [
            {"profile": "llm", "results": {"safety_fail": 0, "pass_rate": 0.5}, "expected": "Safe"},
        ]
        out = sim.simulate(pol.DEFAULT_POLICY, cases, default_profile="llm")
        self.assertEqual(out["summary"]["inconclusive"], 1)
        self.assertFalse(out["results"][0]["match"])

    def test_sweep_monotonic(self):
        cases = [
            {"id": "m1", "profile": "generic", "findings": [{"severity": "medium", "confidence": 1.0}],
             "label": "unsafe"},
        ]
        rows = sim.sweep(pol.DEFAULT_POLICY, cases, [10, 40, 60, 100],
                         mutate=sim.score_threshold_setter("generic", 3, op=">="),
                         default_profile="generic")
        # при низком пороге (10) находка medium (score 25) -> Needs review; при высоком -> Safe (FN)
        self.assertEqual(rows[0]["tp"], 1)
        self.assertEqual(rows[0]["fn"], 0)
        self.assertEqual(rows[-1]["fn"], 1)
        # монотонность: с ростом порога число «пропусков» не убывает
        fns = [r["fn"] for r in rows]
        self.assertEqual(fns, sorted(fns))

    def test_set_path(self):
        p = sim.set_path(pol.DEFAULT_POLICY, "profiles.generic.rules.3.if", "score >= 99")
        self.assertEqual(p["profiles"]["generic"]["rules"][3]["if"], "score >= 99")
        # исходная политика не мутирована
        self.assertEqual(pol.DEFAULT_POLICY["profiles"]["generic"]["rules"][3]["if"], "score >= 60")


if __name__ == "__main__":
    unittest.main()
