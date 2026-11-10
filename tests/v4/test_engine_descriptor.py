#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v4: unit-тесты EngineDescriptor и планировщика RuntimeClass."""
from __future__ import annotations

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "deploy", "v4"))

import engines.descriptor as ed  # noqa: E402

DIGEST = "sha256:" + "a" * 64


class DescriptorTest(unittest.TestCase):
    def _llm(self, **kw):
        base = dict(id="vllm-0.9.2", oci="harbor/engine-vllm@sha256:" + "b" * 64, kind="llm",
                    artifact_kinds=["llm-safetensors"], capabilities={"gpu": True, "protocols": ["raw-http"]},
                    runtime={"resources": {"gpu": 1, "ram_gb": 24}})
        base.update(kw)
        return ed.EngineDescriptor(**base)

    def test_valid(self):
        d = self._llm()
        self.assertEqual(d.validate(), [])
        self.assertTrue(d.is_valid())

    def test_invalid_missing_and_unpinned(self):
        self.assertTrue(ed.EngineDescriptor(id="", oci="x", kind="llm", artifact_kinds=["gguf"]).validate())
        d = ed.EngineDescriptor(id="e", oci="harbor/engine:tag", kind="llm", artifact_kinds=["gguf"])
        self.assertTrue(any("digest" in e for e in d.validate()))
        self.assertTrue(ed.EngineDescriptor(id="e", oci="harbor/e@" + DIGEST, kind="bogus",
                                            artifact_kinds=["gguf"]).validate())
        self.assertTrue(ed.EngineDescriptor(id="e", oci="harbor/e@" + DIGEST, kind="llm",
                                            artifact_kinds=[]).validate())

    def test_compatible(self):
        llm = self._llm()
        self.assertTrue(llm.compatible("llm-safetensors"))
        self.assertTrue(llm.compatible("llm-gguf"))
        self.assertTrue(llm.compatible("gguf"))
        loader = ed.EngineDescriptor(id="l", oci="harbor/l@" + DIGEST, kind="loader",
                                     artifact_kinds=["pickle", "torch"])
        self.assertTrue(loader.compatible("pickle"))
        self.assertFalse(loader.compatible("llm-safetensors"))
        runtime = ed.EngineDescriptor(id="r", oci="harbor/r@" + DIGEST, kind="runtime",
                                      artifact_kinds=["onnx"])
        self.assertTrue(runtime.compatible("onnx"))
        self.assertFalse(runtime.compatible("pickle"))

    def test_needs_gpu_and_profile(self):
        d = self._llm()
        self.assertTrue(d.needs_gpu())
        self.assertEqual(d.resource_profile().get("gpu"), 1)
        c = ed.EngineDescriptor(id="c", oci="harbor/c@" + DIGEST, kind="loader",
                                artifact_kinds=["pickle"], capabilities={"gpu": False})
        self.assertFalse(c.needs_gpu())

    def test_plan_runtime_class(self):
        llm = self._llm()
        cpu = ed.EngineDescriptor(id="c", oci="harbor/c@" + DIGEST, kind="loader",
                                  artifact_kinds=["pickle"], capabilities={"gpu": False})
        # без GPU -> самый наблюдаемый доступный Kata-профиль
        r = ed.plan_runtime_class(cpu, available=["kata", "kata-btf"], gpu_available=False)
        self.assertEqual(r["runtime_class"], "kata-btf")
        self.assertFalse(r["degraded"])
        # GPU доступен внутри Kata -> kata-gpu
        r = ed.plan_runtime_class(llm, available=["kata", "kata-btf", "kata-gpu"], gpu_available=True)
        self.assertEqual(r["runtime_class"], "kata-gpu")
        self.assertFalse(r["degraded"])
        # GPU нужен, kata-gpu нет, но разрешён CPU-fallback -> деградация
        r = ed.plan_runtime_class(llm, available=["kata", "kata-btf"], gpu_available=False,
                                  allow_cpu_fallback=True)
        self.assertEqual(r["runtime_class"], "kata-btf")
        self.assertTrue(r["degraded"])
        # GPU нужен, kata-gpu нет, CPU-fallback запрещён -> отказ
        with self.assertRaises(RuntimeError):
            ed.plan_runtime_class(llm, available=["kata"], gpu_available=False, allow_cpu_fallback=False)

    def test_runtime_class_is_safe(self):
        self.assertTrue(ed.runtime_class_is_safe("kata"))
        self.assertTrue(ed.runtime_class_is_safe("kata-gpu"))
        self.assertFalse(ed.runtime_class_is_safe("nvidia"))
        self.assertFalse(ed.runtime_class_is_safe("runc"))

    def test_from_registry_row(self):
        d = ed.EngineDescriptor.from_registry_row(("sha256:" + "c" * 64, "harbor/engine-vllm:v1", "ui", "llm"))
        self.assertEqual(d.kind, "llm")
        self.assertTrue(d.needs_gpu())
        self.assertIn("llm-safetensors", d.artifact_kinds)
        b = ed.EngineDescriptor.from_registry_row({"digest": DIGEST, "ref": "harbor/sandbox", "source": "builtin"})
        self.assertEqual(b.kind, "loader")

    def test_to_k8s_resources(self):
        d = self._llm()   # resources: gpu=1, ram_gb=24
        r = ed.to_k8s_resources(d)
        self.assertEqual(r["limits"]["memory"], "24Gi")
        self.assertEqual(r["limits"]["nvidia.com/gpu"], "1")
        c = ed.EngineDescriptor(id="c", oci="harbor/c@" + DIGEST, kind="loader",
                                artifact_kinds=["pickle"], capabilities={"gpu": False})
        self.assertEqual(ed.to_k8s_resources(c), {})

    def test_render_start(self):
        d = ed.EngineDescriptor(id="v", oci="harbor/v@" + DIGEST, kind="llm",
                                artifact_kinds=["llm-safetensors"],
                                runtime={"start": "python -m srv --model {{model}} --port 8000"})
        argv = ed.render_start(d, "/model")
        self.assertEqual(argv[0], "/bin/sh")
        self.assertIn("--model /model", argv[-1])
        self.assertIsNone(ed.render_start(ed.EngineDescriptor(id="x", oci="harbor/x@" + DIGEST,
                                                              kind="llm", artifact_kinds=["gguf"]), "/model"))

    def test_roundtrip(self):
        d = self._llm()
        self.assertEqual(ed.EngineDescriptor.from_dict(d.to_dict()).to_dict(), d.to_dict())


if __name__ == "__main__":
    unittest.main()
