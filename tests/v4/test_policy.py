#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v4: unit-тесты политики (скоринг, DSL, вердикт, guardrails)."""
from __future__ import annotations

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "deploy", "v4"))

import scoring.policy as pol  # noqa: E402


class ScoringTest(unittest.TestCase):
    def test_normalize(self):
        f = pol.normalize_finding({"severity": "HIGH", "confidence": 2.0, "check_id": "A-01"})
        self.assertEqual(f["severity"], "high")
        self.assertEqual(f["confidence"], 1.0)
        self.assertEqual(f["id"], "A-01")

    def test_score(self):
        fs = [{"severity": "critical", "confidence": 1.0}, {"severity": "high", "confidence": 0.5}]
        # 100*1 + 60*0.5 = 130
        self.assertEqual(pol.score_findings(fs), 130.0)
        self.assertEqual(pol.severity_counts(fs)["critical"], 1)
        self.assertEqual(pol.category_counts([{"category": "network"}])["network"], 1)


class ParseTest(unittest.TestCase):
    def test_forms(self):
        self.assertEqual(pol.parse_condition("any(critical)"), {"any_severity": "critical"})
        self.assertEqual(pol.parse_condition("coverage < required"), {"coverage_lt_required": True})
        self.assertEqual(pol.parse_condition("score >= 75"), {"score_cmp": [">=", 75.0]})
        self.assertEqual(pol.parse_condition("safety_fail > 0"), {"safety_fail_cmp": [">", 0.0]})
        self.assertEqual(pol.parse_condition("pass_rate < 1.0"), {"pass_rate_cmp": ["<", 1.0]})
        self.assertEqual(pol.parse_condition("count(high) >= 2"), {"count_cmp": ["high", ">=", 2]})
        self.assertEqual(pol.parse_condition(True), {"always": True})

    def test_and_or(self):
        c = pol.parse_condition("any(high) and score >= 10")
        self.assertIn("and", c)
        c2 = pol.parse_condition("any(critical) or pass_rate < 0.5")
        self.assertIn("or", c2)

    def test_invalid(self):
        with self.assertRaises(ValueError):
            pol.parse_condition("drop table findings")

    def test_parse_text_dsl(self):
        pol.parse_text_dsl(pol.DEFAULT_POLICY)  # не бросает
        bad = {"profiles": {"x": {"rules": [{"if": "nonsense", "then": "Safe"}]}}}
        with self.assertRaises(ValueError):
            pol.parse_text_dsl(bad)


class VerdictTest(unittest.TestCase):
    def test_llm_reproduces_v3(self):
        # safety_fail > 0 -> Needs review
        v = pol.evaluate([], coverage=None, results={"safety_fail": 3, "pass_rate": 0.9},
                         policy=pol.DEFAULT_POLICY, profile="llm")
        self.assertEqual(v["verdict"], "Needs review")
        # pass_rate == 1, без находок -> Safe
        v = pol.evaluate([], coverage=None, results={"safety_fail": 0, "pass_rate": 1.0},
                         policy=pol.DEFAULT_POLICY, profile="llm")
        self.assertEqual(v["verdict"], "Safe")
        self.assertEqual(v["action"], "allow")
        # safety_fail == 0, pass_rate < 1 -> Inconclusive
        v = pol.evaluate([], coverage=None, results={"safety_fail": 0, "pass_rate": 0.8},
                         policy=pol.DEFAULT_POLICY, profile="llm")
        self.assertEqual(v["verdict"], "Inconclusive")
        self.assertEqual(v["action"], "quarantine")

    def test_critical_blocks(self):
        v = pol.evaluate([{"severity": "critical", "confidence": 0.9}], coverage=None, results={},
                         policy=pol.DEFAULT_POLICY, profile="generic")
        self.assertEqual(v["verdict"], "Malicious")
        self.assertEqual(v["action"], "block")

    def test_coverage_guardrail(self):
        # требуются process+file; наблюдаем только process -> Inconclusive (нет Safe)
        v = pol.evaluate([], coverage={"domains": ["process"]}, results={},
                         policy=pol.DEFAULT_POLICY, profile="generic")
        self.assertFalse(v["coverage_ok"])
        self.assertEqual(v["verdict"], "Inconclusive")
        # покрытие не измерялось -> guardrail не вводится
        v2 = pol.evaluate([], coverage=None, results={}, policy=pol.DEFAULT_POLICY, profile="generic")
        self.assertTrue(v2["coverage_ok"])
        self.assertEqual(v2["verdict"], "Safe")

    def test_custom_policy(self):
        custom = {
            "id": "strict", "version": 2, "actions": pol.DEFAULT_ACTIONS,
            "profiles": {"generic": {
                "weights": pol.DEFAULT_WEIGHTS,
                "coverage_min": {},
                "rules": [
                    {"if": "score >= 20", "then": "Malicious"},
                    {"if": "any(medium)", "then": "Needs review"},
                    {"if": True, "then": "Safe"},
                ],
            }},
        }
        v = pol.evaluate([{"severity": "medium", "confidence": 1.0}], results={}, policy=custom,
                         profile="generic")
        # 25 >= 20 -> Malicious
        self.assertEqual(v["verdict"], "Malicious")
        self.assertEqual(v["policy"]["version"], 2)


if __name__ == "__main__":
    unittest.main()
