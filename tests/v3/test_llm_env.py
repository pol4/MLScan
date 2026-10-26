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


class GpuEnvTest(unittest.TestCase):
    DIG = "ghcr.io/ggml-org/llama.cpp@sha256:" + "c" * 64

    def test_gpu_job_nvidia_runtime(self):
        job = llm_env.make_scan_job(scan_id="g1", engine_image=self.DIG, model_sha256="b" * 64,
                                    model_key="t/m.bin", resources={"gpu": 1, "ram_gb": 32, "disk_gb": 50},
                                    runtime_class="nvidia", mount_dev=True, cuda_visible_devices="1")
        ok, why = llm_env.validate_job(job); self.assertTrue(ok, why)
        spec = job["spec"]["template"]["spec"]
        self.assertEqual(spec["runtimeClassName"], "nvidia")
        eng = spec["containers"][0]
        self.assertEqual(eng["resources"]["limits"]["nvidia.com/gpu"], 1)
        self.assertIn({"name": "NVIDIA_VISIBLE_DEVICES", "value": "all"}, eng["env"])
        self.assertIn({"name": "CUDA_VISIBLE_DEVICES", "value": "1"}, eng["env"])
        self.assertTrue(any(v["name"] == "dev" and v["hostPath"]["path"] == "/dev" for v in spec["volumes"]))

    def test_kata_default_unchanged(self):
        job = llm_env.make_scan_job(scan_id="k1", engine_image=self.DIG, model_sha256="b" * 64, model_key="t/m.bin")
        self.assertEqual(job["spec"]["template"]["spec"]["runtimeClassName"], "kata")
        self.assertEqual([v["name"] for v in job["spec"]["template"]["spec"]["volumes"]], ["model", "events"])

    def test_bad_runtime_rejected(self):
        job = llm_env.make_scan_job(scan_id="x", engine_image=self.DIG, model_sha256="b" * 64,
                                    model_key="t/m.bin", runtime_class="bogus")
        self.assertFalse(llm_env.validate_job(job)[0])

    # --- N2: job теста bundle (реальный движок + вопросы) ---
    def _llm_job(self, gpu=True, runtime_class="nvidia"):
        return llm_env.make_llama_test_job(
            bundle_id="b-test123", engine_image="reg/llama@sha256:" + "a" * 64,
            model_url="https://s3/presigned", model_sha256="b" * 64,
            prompts=[{"id": "q1", "prompt": "привет"}, {"id": "q2", "prompt": "2+2"}],
            testing_url="http://mlscan-testing.mlscan-testing.svc.cluster.local:8080",
            api_key="runtoken", prompt_set="ps-test", gpu=gpu, runtime_class=runtime_class)

    def test_llm_test_job_requires_digest(self):
        with self.assertRaises(ValueError):
            llm_env.make_llama_test_job(bundle_id="b", engine_image="reg/x:tag", model_url="https://u",
                                        model_sha256="c" * 64, prompts=[], testing_url="http://t", api_key="k")

    def test_llm_test_job_requires_model_url(self):
        with self.assertRaises(ValueError):
            llm_env.make_llama_test_job(bundle_id="b", engine_image="reg/x@sha256:" + "a" * 64,
                                        model_url="", model_sha256="c" * 64, prompts=[],
                                        testing_url="http://t", api_key="k")

    def test_llm_test_job_containers_and_gpu(self):
        job = self._llm_job(gpu=True)
        spec = job["spec"]["template"]["spec"]
        names = [c["name"] for c in spec["containers"]]
        self.assertEqual(names, ["engine", "probe"])
        self.assertEqual([c["name"] for c in spec["initContainers"]], ["model-fetcher"])
        engine = spec["containers"][0]
        self.assertEqual(engine["image"], "reg/llama@sha256:" + "a" * 64)
        self.assertEqual(engine["resources"]["limits"]["nvidia.com/gpu"], 1)
        self.assertIn("99", engine["args"])
        self.assertEqual(spec["runtimeClassName"], "nvidia")
        self.assertEqual(spec["volumes"][1]["hostPath"]["path"], "/dev")
        self.assertFalse(spec["automountServiceAccountToken"])

    def test_llm_test_job_cpu_mode(self):
        spec = self._llm_job(gpu=False, runtime_class="kata")["spec"]["template"]["spec"]
        limits = spec["containers"][0]["resources"]["limits"]
        self.assertNotIn("nvidia.com/gpu", limits)
        self.assertIn("0", spec["containers"][0]["args"])
        self.assertEqual(len(spec["volumes"]), 1)          # без /dev
        self.assertEqual(spec["runtimeClassName"], "kata")

    def test_llm_test_job_probe_payload(self):
        spec = self._llm_job()["spec"]["template"]["spec"]
        probe = spec["containers"][1]
        env = {e["name"]: e["value"] for e in probe["env"]}
        self.assertIn('"q1"', env["PROMPTS_JSON"])
        self.assertEqual(env["BUNDLE_ID"], "b-test123")
        self.assertEqual(env["MLSCAN_KEY"], "runtoken")
        src = probe["command"][2]
        self.assertIn("/llm/score", src)
        fetch = spec["initContainers"][0]["command"][2]
        self.assertIn("SHA_MISMATCH", fetch)               # проверка sha модели


if __name__ == "__main__":
    unittest.main(verbosity=2)
