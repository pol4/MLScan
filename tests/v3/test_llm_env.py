#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""L1: unit/contract-тесты единой Kata-среды (Job для LLM-инференса) и ресурсной проверки."""
from __future__ import annotations

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "deploy", "v3", "llm"))

import llm_env  # noqa: E402

DIGEST = "mlscan-registry/t/vllm@sha256:" + "a" * 64


class ResourceCheckTest(unittest.TestCase):
    def test_enough(self):
        ok, _ = llm_env.resource_check({"gpu": 1, "ram_gb": 64, "disk_gb": 100},
                                       {"gpu": 2, "ram_gb": 256, "disk_gb": 500})
        self.assertTrue(ok)

    def test_insufficient_gpu(self):
        ok, why = llm_env.resource_check({"gpu": 4}, {"gpu": 1})
        self.assertFalse(ok); self.assertIn("gpu", why)

    def test_insufficient_ram(self):
        ok, why = llm_env.resource_check({"ram_gb": 512}, {"ram_gb": 64})
        self.assertFalse(ok); self.assertIn("ram_gb", why)

    def test_zero_required(self):
        self.assertTrue(llm_env.resource_check({}, {})[0])


class JobManifestTest(unittest.TestCase):
    def job(self, **kw):
        base = dict(scan_id="s1", engine_image=DIGEST, model_sha256="b" * 64,
                    model_key="tenant/t/obj.bin", resources={"gpu": 1, "ram_gb": 64, "disk_gb": 100},
                    prompt_set="ps-v1")
        base.update(kw)
        return llm_env.make_scan_job(**base)

    def test_valid_job(self):
        ok, why = llm_env.validate_job(self.job())
        self.assertTrue(ok, why)

    def test_containers_and_init(self):
        spec = self.job()["spec"]["template"]["spec"]
        self.assertEqual([c["name"] for c in spec["containers"]],
                         ["engine", "tetragon-agent", "probe-runner"])
        self.assertEqual(spec["initContainers"][0]["name"], "model-fetcher")
        self.assertEqual(spec["runtimeClassName"], "kata")

    def test_shared_volumes(self):
        vols = {v["name"] for v in self.job()["spec"]["template"]["spec"]["volumes"]}
        self.assertEqual(vols, {"model", "events"})

    def test_gpu_limit(self):
        lim = self.job()["spec"]["template"]["spec"]["containers"][0]["resources"]["limits"]
        self.assertEqual(lim["nvidia.com/gpu"], 1)

    def test_engine_digest_required(self):
        ok, why = llm_env.validate_job(self.job(engine_image="vllm:latest"))
        self.assertFalse(ok); self.assertIn("digest", why)

    def test_probe_uses_localhost(self):
        args = self.job()["spec"]["template"]["spec"]["containers"][2]["args"]
        self.assertTrue(any("127.0.0.1" in a for a in args))


if __name__ == "__main__":
    unittest.main(verbosity=2)
