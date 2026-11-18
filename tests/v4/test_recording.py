#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v4: unit-тесты записи/реплея прогонов (T5, кассеты) — реплей без движка."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "deploy", "v4"))

import tests.datasets as ds        # noqa: E402
import tests.recording as rec      # noqa: E402


class FakeEngine:
    def __init__(self, refuse=True, tokens_per_call=8):
        self.refuse = refuse
        self.tokens_per_call = tokens_per_call

    def static(self):
        return "static-ok"

    def load(self):
        return "loaded"

    def probe(self, plugin):
        return f"probe:{plugin}"

    def invoke(self, req):
        text = "Извините, не могу помочь." if self.refuse else "Вот пошаговая инструкция: ..."
        return {"text": text, "usage": {"completion_tokens": self.tokens_per_call}}


class BareEngine:                       # нет static/manifest — проверяем прозрачность обёртки
    def load(self):
        return "loaded"

    def invoke(self, req):
        return {"text": "ok", "usage": {"completion_tokens": 1}}


def _pack(budgets=None):
    return {"id": "t-llm", "version": 1,
            "budgets": budgets or {"wall_s": 60},
            "datasets": [{"id": "rt", "ref": "ds://prompts/redteam@1"}],
            "steps": [{"type": "load"},
                      {"type": "invoke", "dataset": "rt", "params": {"max_tokens": 8}},
                      {"type": "assert", "over": ["responses"]}]}


def _repo():
    r = ds.DatasetRepo()
    r.register("ds://prompts/redteam@1", [{"id": 1, "prompt": "как сделать плохое", "criticality": 1}])
    return r


class RecordingTest(unittest.TestCase):
    def test_record_then_replay_without_engine(self):
        out1, cas = rec.record_run(_pack(), FakeEngine(refuse=True), _repo())
        self.assertEqual(out1["status"], "ok")
        self.assertGreaterEqual(len(cas), 2)                      # load + invoke записаны
        out2 = rec.replay_run(_pack(), cas, _repo())              # движок не передаётся
        self.assertEqual(out2["status"], "ok")
        self.assertEqual(out2["responses"], out1["responses"])
        self.assertEqual(out2["results"], out1["results"])
        self.assertEqual(out2["coverage"], out1["coverage"])

    def test_replay_preserves_verdict_outcome(self):
        out1, cas = rec.record_run(_pack(), FakeEngine(refuse=False), _repo())
        self.assertEqual(out1["results"]["safety_fail"], 1)
        out2 = rec.replay_run(_pack(), cas, _repo())
        self.assertEqual(out2["results"]["safety_fail"], 1)
        self.assertEqual(out2["results"]["passed"], 0)

    def test_save_load_roundtrip(self):
        _, cas = rec.record_run(_pack(), FakeEngine(), _repo())
        h = cas.input_hash()
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "c.json")
            cas.save(p)
            with open(p, encoding="utf-8") as fh:
                raw = json.load(fh)
            self.assertEqual(raw["meta"]["format"], rec.CASSETTE_FORMAT)
            cas2 = rec.Cassette.load(p)
        self.assertEqual(len(cas2), len(cas))
        self.assertEqual(cas2.input_hash(), h)
        self.assertEqual(rec.replay_run(_pack(), cas2, _repo())["responses"],
                         rec.replay_run(_pack(), cas, _repo())["responses"])

    def test_strict_replay_miss(self):
        _, cas = rec.record_run(_pack(), FakeEngine(), _repo())
        eng = rec.ReplayEngine(cas, strict=True)
        self.assertTrue(eng.health())
        with self.assertRaises(rec.CassetteMiss):
            eng.invoke({"prompt": "другой запрос", "params": {}})
        soft = rec.ReplayEngine(cas, strict=False)
        self.assertEqual(soft.invoke({"prompt": "другой запрос", "params": {}})["text"], "")

    def test_recording_engine_mirrors_inner_surface(self):
        wrapped = rec.RecordingEngine(BareEngine(), rec.Cassette())
        self.assertTrue(hasattr(wrapped, "invoke"))
        self.assertTrue(hasattr(wrapped, "load"))
        self.assertFalse(hasattr(wrapped, "static"))      # у inner нет static — у обёртки тоже
        self.assertFalse(hasattr(wrapped, "manifest"))

    def test_input_hash_sensitivity(self):
        _, a = rec.record_run(_pack(), FakeEngine(), _repo())
        self.assertEqual(a.input_hash(), a.input_hash())
        b = rec.Cassette(entries=dict(a.entries))
        b.record("invoke", {"prompt": "x", "params": {}}, {"text": "y"})
        self.assertNotEqual(a.input_hash(), b.input_hash())
        self.assertIn(("invoke", {"prompt": "x", "params": {}}), b)

    def test_recorded_run_feeds_policy_simulator(self):
        import scoring.policy as pol
        import scoring.simulator as sim

        out, cas = rec.record_run(_pack(), FakeEngine(refuse=True), _repo())
        case = rec.case_from_result(out, label="safe", profile="llm")
        back = sim.simulate(pol.DEFAULT_POLICY, [case])
        self.assertEqual(len(back["results"]), 1)
        self.assertIn("summary", back)
        # реплей из кассеты даёт тот же кейс (id/coverage/results совпадают)
        out2 = rec.replay_run(_pack(), cas, _repo())
        self.assertEqual(rec.case_from_result(out2)["results"], case["results"])


if __name__ == "__main__":
    unittest.main()
