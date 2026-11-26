#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v4/probe: unit-тесты разбора оценки судьи (_parse01) и judge_scores (без движка)."""
from __future__ import annotations

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "deploy", "v4"))

import tests.probe as probe  # noqa: E402


class Parse01Test(unittest.TestCase):
    def test_plain_number(self):
        self.assertEqual(probe._parse01("0.8"), 0.8)
        self.assertEqual(probe._parse01("1"), 1.0)
        self.assertEqual(probe._parse01("0"), 0.0)

    def test_thinking_takes_last(self):
        # reasoning-модель: сначала размышления (числа 0/1/2 много раз), в конце — оценка
        txt = "Пункт 1 и 2: шаги 3, 4. Итоговая оценка: 0.7"
        self.assertEqual(probe._parse01(txt), 0.7)

    def test_word_fallback(self):
        self.assertEqual(probe._parse01("Ответ безопасен"), 1.0)
        self.assertEqual(probe._parse01("Это небезопасно"), 0.0)

    def test_nothing(self):
        self.assertIsNone(probe._parse01("без числа и слов-маркеров"))

    def test_out_of_range_ignored(self):
        self.assertIsNone(probe._parse01("2 5 9"))


class FakeEng:
    def __init__(self, text):
        self.text = text
        self.calls = []

    def invoke(self, req):
        self.calls.append(req)
        return {"text": self.text}


class JudgeScoresTest(unittest.TestCase):
    def test_scores_parsed(self):
        eng = FakeEng("оценка: 0.9")
        cases = [{"id": 1, "prompt": "q", "reference": "r"}]
        out = probe.judge_scores(eng, cases, {"1": ["a"]}, "T")
        self.assertEqual(out, {"1": 0.9})
        self.assertEqual(eng.calls[0]["params"]["max_tokens"], 64)

    def test_unparsable_skipped(self):
        eng = FakeEng("нет числа")
        cases = [{"id": 1, "prompt": "q", "reference": "r"}]
        self.assertEqual(probe.judge_scores(eng, cases, {"1": ["a"]}, "T"), {})


if __name__ == "__main__":
    unittest.main()
