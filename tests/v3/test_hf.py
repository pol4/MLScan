#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""H1: unit-тесты выбора файлов/квантизации, фильтров поиска и плана докачки HF."""
from __future__ import annotations

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "deploy", "v3", "ingest"))

import hf  # noqa: E402


class HfTest(unittest.TestCase):
    def test_parse_quantization(self):
        self.assertEqual(hf.parse_quantization("model-Q4_K_M.gguf"), "Q4_K_M")
        self.assertEqual(hf.parse_quantization("tinyllama.Q8_0.gguf"), "Q8_0")
        self.assertEqual(hf.parse_quantization("model.safetensors"), "")

    def test_select_by_quantization(self):
        files = ["a-Q4_K_M.gguf", "a-Q8_0.gguf", "a.safetensors", "README.md"]
        self.assertEqual(hf.select_files(files, quantization="Q8_0"), ["a-Q8_0.gguf"])
        self.assertEqual(hf.select_files(files, quantization="Q4_K_M"), ["a-Q4_K_M.gguf"])

    def test_select_priority(self):
        files = ["a-F16.gguf", "a-Q4_K_M.gguf", "a-Q8_0.gguf", "b.txt"]
        sel = hf.select_files(files)
        self.assertEqual(sel[0], "a-Q4_K_M.gguf")   # приоритет Q4_K_M
        self.assertTrue(all(f.endswith(".gguf") for f in sel))

    def test_filter_search(self):
        items = [
            {"id": "Qwen/Qwen2-0.5B-Instruct-GGUF", "tags": ["text-generation", "gguf"],
             "files": ["q4_k_m.gguf", "q8_0.gguf"]},
            {"id": "TheBloke/TinyLlama-1.1B-GGUF", "tags": ["text-generation"], "files": ["tiny.Q5_K_M.gguf"]},
            {"id": "openai/whisper-small", "tags": ["automatic-speech-recognition"], "files": []},
        ]
        self.assertEqual([x["id"] for x in hf.filter_search(items, type_="text-generation")],
                         ["Qwen/Qwen2-0.5B-Instruct-GGUF", "TheBloke/TinyLlama-1.1B-GGUF"])
        self.assertEqual([x["id"] for x in hf.filter_search(items, vendor="TheBloke")],
                         ["TheBloke/TinyLlama-1.1B-GGUF"])
        self.assertEqual([x["id"] for x in hf.filter_search(items, quantization="Q8_0")],
                         ["Qwen/Qwen2-0.5B-Instruct-GGUF"])
        self.assertEqual([x["id"] for x in hf.filter_search(items, name="tinyllama")],
                         ["TheBloke/TinyLlama-1.1B-GGUF"])

    def test_resume_plan(self):
        p = hf.resume_plan(1000, 400, etag="etag1", served_etag="etag1")
        self.assertEqual(p["offset"], 400); self.assertEqual(p["range_header"], "bytes=400-")
        self.assertEqual(p["remaining"], 600); self.assertFalse(p["restart"])
        # ETag изменился -> перезагрузка с нуля
        p2 = hf.resume_plan(1000, 400, etag="etag1", served_etag="etag2")
        self.assertTrue(p2["restart"]); self.assertEqual(p2["offset"], 0)
        # завершено
        p3 = hf.resume_plan(1000, 1000)
        self.assertTrue(p3["done"])

    # --- N5: пределы загрузки (отказ от неизвестного размера, лимиты файла/суммы) ---
    def test_check_limits_unknown_size_refused(self):
        ok, why = hf.check_limits(0, 0, max_file=1024, max_total=4096)
        self.assertFalse(ok)
        self.assertIn("unknown size", why)

    def test_check_limits_file_cap(self):
        self.assertTrue(hf.check_limits(1024, 0, max_file=1024)[0])
        ok, why = hf.check_limits(1025, 0, max_file=1024)
        self.assertFalse(ok)
        self.assertIn("file too large", why)

    def test_check_limits_total_cap(self):
        # 3 файла по 1 КиБ при лимите 4 КиБ: третий упирается в суммарный лимит
        self.assertTrue(hf.check_limits(1024, 2048, max_total=4096)[0])
        self.assertTrue(hf.check_limits(1024, 3072, max_total=4096)[0])   # ровно лимит — можно
        ok, why = hf.check_limits(1025, 3072, max_total=4096)              # 4097 > 4096 — отказ
        self.assertFalse(ok)
        self.assertIn("total limit exceeded", why)

    def test_check_limits_no_limits(self):
        self.assertTrue(hf.check_limits(10 ** 12, 0)[0])        # 0 = без лимита
        self.assertFalse(hf.check_limits(-5, 0)[0])             # отрицательный размер = неизвестен


if __name__ == "__main__":
    unittest.main(verbosity=2)
