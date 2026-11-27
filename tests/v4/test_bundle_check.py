#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v3/v4: unit-тесты предполётной проверки bundle (bundle_check.preflight_manifest)."""
from __future__ import annotations

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "deploy", "v3", "llm"))

import bundle_check as bc  # noqa: E402

VLLM = "engine-vllm:v0.9.2"
GGUF = "engine-llama-cpp:cuda"


def _dir(files):
    return {"dir": True, "files": [{"name": n} for n in files]}


class PreflightTest(unittest.TestCase):
    def test_ok_dir_llm(self):
        reasons, info = bc.preflight_manifest(
            VLLM, "a" * 64, engine_ok=True, key="k",
            meta=_dir(["config.json", "model-00001-of-00002.safetensors"]))
        self.assertEqual(reasons, [])
        self.assertTrue(info["has_config"] and info["has_weights"] and info["engine_is_dir"])

    def test_missing_config(self):
        reasons, _ = bc.preflight_manifest(
            VLLM, "a" * 64, engine_ok=True, key="k", meta=_dir(["weights.safetensors"]))
        self.assertTrue(any("config.json" in r for r in reasons))

    def test_missing_weights(self):
        reasons, _ = bc.preflight_manifest(
            VLLM, "a" * 64, engine_ok=True, key="k", meta=_dir(["config.json", "README.md"]))
        self.assertTrue(any("весов" in r for r in reasons))

    def test_no_sha(self):
        reasons, _ = bc.preflight_manifest(VLLM, "", engine_ok=True, key="", meta={})
        self.assertEqual(len(reasons), 1)

    def test_engine_not_found(self):
        reasons, _ = bc.preflight_manifest(VLLM, "a" * 64, engine_ok=False, key="k", meta=_dir(["config.json"]))
        self.assertTrue(any("движок" in r for r in reasons))

    def test_artifact_missing(self):
        reasons, _ = bc.preflight_manifest(VLLM, "a" * 64, engine_ok=True, key="", meta={})
        self.assertTrue(any("артефакт" in r for r in reasons))

    def test_single_file_engine_ok(self):
        # llama.cpp (не dir-движок): одиночный gguf допустим
        reasons, info = bc.preflight_manifest(
            GGUF, "b" * 64, engine_ok=True, key="k", meta={"dir": False, "files": [{"name": "m.gguf"}]})
        self.assertEqual(reasons, [])
        self.assertFalse(info["engine_is_dir"])

    def test_dir_flag_without_listing_not_rejected(self):
        # dir=True, но список файлов пуст (нет манифеста) — не отвергаем здесь (проверяется догрузкой каталога)
        reasons, _ = bc.preflight_manifest(VLLM, "a" * 64, engine_ok=True, key="k", meta={"dir": True, "files": []})
        self.assertEqual(reasons, [])


if __name__ == "__main__":
    unittest.main()
