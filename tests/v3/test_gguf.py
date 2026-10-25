#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""U2: unit-тесты парсера GGUF и авто-классификации по metadata (без подсказки)."""
from __future__ import annotations

import os
import struct
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "deploy", "v3", "llm"))

import gguf  # noqa: E402
import classifier  # noqa: E402


def _s(x: str) -> bytes:
    e = x.encode()
    return struct.pack("<Q", len(e)) + e


def _kv_str(key: str, val: str) -> bytes:
    return _s(key) + struct.pack("<I", gguf.T_STRING) + _s(val)


def _kv_u32(key: str, val: int) -> bytes:
    return _s(key) + struct.pack("<I", gguf.T_UINT32) + struct.pack("<I", val)


def make_gguf(arch="llama", version=3, tensors=1) -> bytes:
    head = gguf.MAGIC + struct.pack("<I", version) + struct.pack("<Q", tensors) + struct.pack("<Q", 2)
    head += _kv_str("general.architecture", arch)
    head += _kv_u32("llama.block_count", 32)
    return head + b"\x00" * 512


class GgufTest(unittest.TestCase):
    def test_parse_meta(self):
        m = gguf.parse_gguf_meta(make_gguf("qwen2"))
        self.assertEqual(m["version"], 3)
        self.assertEqual(m["tensors"], 1)
        self.assertEqual(m["meta"]["general.architecture"], "qwen2")
        self.assertEqual(m["meta"]["llama.block_count"], 32)

    def test_not_gguf(self):
        self.assertEqual(gguf.parse_gguf_meta(b"NOPE" + b"\x00" * 10), {})
        self.assertEqual(gguf.architecture(b"not a model"), "")

    def test_architecture_helper(self):
        self.assertEqual(gguf.architecture(make_gguf("mistral")), "mistral")

    def test_auto_classify_from_gguf(self):
        meta = gguf.parse_gguf_meta(make_gguf("llama"))["meta"]
        prof = classifier.classify(filenames=["model.gguf"], gguf_meta=meta)
        self.assertTrue(prof["is_llm"])
        self.assertEqual(prof["family"], "llama")
        self.assertGreaterEqual(prof["confidence"], 0.5)

    def test_truncated_gguf(self):
        ok = gguf.parse_gguf_meta(gguf.MAGIC + struct.pack("<I", 3) + struct.pack("<Q", 1))  # нет n_kv
        self.assertEqual(ok, {})


if __name__ == "__main__":
    unittest.main(verbosity=2)
