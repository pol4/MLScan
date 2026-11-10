#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v4: unit-тесты сборки плана проверки (движок + пакеты + наблюдение)."""
from __future__ import annotations

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "deploy", "v4"))

import engines.descriptor as ed   # noqa: E402
import engines.plan as plan       # noqa: E402

D = "sha256:" + "a" * 64


def _llm():
    return ed.EngineDescriptor(id="vllm-0.9.2", oci="harbor/e@" + D, kind="llm",
                               artifact_kinds=["llm-safetensors"],
                               capabilities={"gpu": True, "protocols": ["raw-http"]},
                               runtime={"resources": {"gpu": 1, "ram_gb": 24}})


def _loader():
    return ed.EngineDescriptor(id="sandbox-loader", oci="harbor/s@" + D, kind="loader",
                               artifact_kinds=["pickle", "safetensors"], capabilities={"gpu": False})


PACKS = [{"id": "llm-basic", "version": 1, "hash": "sha256:x",
          "steps": [{"type": "load"}, {"type": "invoke"}, {"type": "assert"}],
          "observation": {"require": ["process", "network"]}, "budgets": {"wall_s": 900}}]


class PlanTest(unittest.TestCase):
    def test_gpu_in_kata(self):
        p = plan.build_plan(_llm(), PACKS, artifact_kind="llm-safetensors", engine="kind:llm",
                            available=["kata", "kata-btf", "kata-gpu"], gpu_available=True,
                            policy={"id": "default", "version": 3})
        self.assertEqual(p["engine"]["runtime_class"], "kata-gpu")
        self.assertFalse(p["engine"]["degraded"])
        self.assertEqual(p["engine"]["resources"].get("gpu"), 1)
        self.assertEqual(p["testpacks"][0]["steps"], ["load", "invoke", "assert"])
        self.assertEqual(p["observation"]["require"], ["process", "network"])
        self.assertEqual(p["policy"]["version"], 3)

    def test_degraded_cpu_fallback(self):
        p = plan.build_plan(_llm(), PACKS, artifact_kind="llm-safetensors", engine="kind:llm",
                            available=["kata", "kata-btf"], gpu_available=False, allow_cpu_fallback=True)
        self.assertEqual(p["engine"]["runtime_class"], "kata-btf")
        self.assertTrue(p["engine"]["degraded"])

    def test_refuse_without_gpu(self):
        p = plan.build_plan(_llm(), PACKS, available=["kata"], gpu_available=False, allow_cpu_fallback=False)
        self.assertEqual(p["engine"]["runtime_class"], "")
        self.assertTrue(p["engine"]["degraded"])
        self.assertIn("GPU", p["engine"]["reason"])

    def test_cpu_loader(self):
        p = plan.build_plan(_loader(), [], artifact_kind="pickle", available=["kata"])
        self.assertEqual(p["engine"]["runtime_class"], "kata")
        self.assertFalse(p["engine"]["degraded"])
        self.assertEqual(p["testpacks"], [])
        self.assertEqual(p["observation"]["require"], [])

    def test_union_observation(self):
        packs = [{"id": "a", "observation": {"require": ["process"]}},
                 {"id": "b", "observation": {"require": ["process", "file"]}}]
        p = plan.build_plan(_loader(), packs, available=["kata"])
        self.assertEqual(p["observation"]["require"], ["process", "file"])


if __name__ == "__main__":
    unittest.main()
