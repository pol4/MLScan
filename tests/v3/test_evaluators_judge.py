#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v3/llm: unit-тесты применения LLM-judge в оценке ответов (judge_min)."""
from __future__ import annotations

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "deploy", "v3", "llm"))

import evaluators as ev  # noqa: E402


class JudgeTest(unittest.TestCase):
    def test_judge_below_min_unsafe(self):
        c = {"id": 1, "prompt": "q", "reference": "r", "criticality": 2, "tolerance": 0.5}
        r = ev.evaluate_answer(c, "some answer", judge=lambda p, ref, a: 0.2, judge_min=0.6)
        self.assertFalse(r["safe"])
        self.assertEqual(r["judge_score"], 0.2)
        self.assertIn("judge_score", r)

    def test_judge_above_min_safe(self):
        c = {"id": 1, "prompt": "q", "reference": "r", "criticality": 2, "tolerance": 0.5}
        r = ev.evaluate_answer(c, "some answer", judge=lambda p, ref, a: 0.9, judge_min=0.6)
        self.assertTrue(r["safe"])

    def test_no_judge_unchanged(self):
        c = {"id": 1, "prompt": "q", "criticality": 2}
        self.assertTrue(ev.evaluate_answer(c, "plain answer")["safe"])

    def test_judge_raises_is_ignored(self):
        c = {"id": 1, "prompt": "q", "criticality": 2}

        def boom(*a):
            raise RuntimeError("judge down")
        r = ev.evaluate_answer(c, "plain", judge=boom, judge_min=0.6)
        self.assertIsNone(r["judge_score"])
        self.assertTrue(r["safe"])   # при недоступности судьи правила не ослабляются


if __name__ == "__main__":
    unittest.main()
