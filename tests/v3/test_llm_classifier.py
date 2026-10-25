#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""L0: unit-тесты классификатора LLM и binding/bundle."""
from __future__ import annotations

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "deploy", "v3", "llm"))

import binding  # noqa: E402
import classifier  # noqa: E402

DIGEST = "mlscan-registry/t/vllm@sha256:" + "a" * 64
MSHA = "b" * 64


class ClassifierTest(unittest.TestCase):
    def test_llm_by_config_type(self):
        r = classifier.classify(filenames=["config.json", "tokenizer.json", "model.safetensors"],
                                config={"model_type": "qwen2"}, size_bytes=8 * 1024 ** 3)
        self.assertTrue(r["is_llm"])
        self.assertEqual(r["family"], "qwen2")
        self.assertGreaterEqual(r["confidence"], 0.5)
        self.assertTrue(r["suggested_engines"])
        self.assertEqual(r["recommended_resources"]["gpu"], 1)
        self.assertIn("config.model_type=qwen2", r["evidence"])

    def test_llm_by_architecture(self):
        r = classifier.classify(config={"architectures": ["LlamaForCausalLM"]},
                                filenames=["tokenizer.model"])
        self.assertTrue(r["is_llm"]); self.assertEqual(r["family"], "llama")

    def test_gguf_metadata(self):
        r = classifier.classify(filenames=["model.gguf"],
                                gguf_meta={"general.architecture": "llama"})
        self.assertTrue(r["is_llm"]); self.assertEqual(r["family"], "llama")

    def test_not_llm(self):
        r = classifier.classify(filenames=["config.yaml", "weights.npz"], config={})
        self.assertFalse(r["is_llm"])
        self.assertEqual(r["suggested_engines"], [])

    def test_low_confidence_not_llm(self):
        r = classifier.classify(filenames=["vocab.json"])  # только токенизатор
        self.assertFalse(r["is_llm"])
        self.assertLess(r["confidence"], 0.5)


class BindingTest(unittest.TestCase):
    def test_bundle_id_stable_and_sensitive(self):
        b1 = binding.bundle_id(DIGEST, MSHA, {"entrypoint": "vllm serve"}, "ps-v1", "det-v7", "pol-v12")
        b2 = binding.bundle_id(DIGEST, MSHA, {"entrypoint": "vllm serve"}, "ps-v1", "det-v7", "pol-v12")
        self.assertEqual(b1, b2)
        self.assertTrue(b1.startswith("b-"))
        # любое изменение → новый bundle_id
        self.assertNotEqual(b1, binding.bundle_id(DIGEST, MSHA, {"entrypoint": "vllm serve"},
                                                  "ps-v2", "det-v7", "pol-v12"))
        self.assertNotEqual(b1, binding.bundle_id(DIGEST, "c" * 64, {"entrypoint": "vllm serve"},
                                                  "ps-v1", "det-v7", "pol-v12"))

    def test_make_and_validate(self):
        b = binding.make_bundle(image_digest=DIGEST, model_sha256=MSHA,
                                engine_manifest={"entrypoint": "vllm serve", "api": "openai:/v1"},
                                prompt_set="ps-v1", detectors="det-v7", policy="pol-v12",
                                tenant="ci-team")
        ok, why = binding.validate_bundle(b)
        self.assertTrue(ok, why)
        self.assertEqual(b["engine_image"], DIGEST)

    def test_validate_rejects(self):
        bad = binding.make_bundle(image_digest="vllm:latest", model_sha256=MSHA)
        self.assertFalse(binding.validate_bundle(bad)[0])          # не по digest
        bad2 = binding.make_bundle(image_digest=DIGEST, model_sha256="short")
        self.assertFalse(binding.validate_bundle(bad2)[0])
        tampered = binding.make_bundle(image_digest=DIGEST, model_sha256=MSHA)
        tampered["prompt_set"] = "ps-v999"                          # рассинхрон с bundle_id
        self.assertFalse(binding.validate_bundle(tampered)[0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
