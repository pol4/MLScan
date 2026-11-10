#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v4: unit-тесты TestPack и Dataset."""
from __future__ import annotations

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "deploy", "v4"))

import tests.testpack as tp      # noqa: E402
import tests.datasets as ds      # noqa: E402


class TestPackTest(unittest.TestCase):
    def test_valid_and_hash(self):
        p = {"id": "p", "version": 2, "steps": [{"type": "load"}, {"type": "assert"}]}
        self.assertEqual(tp.validate_pack(p), [])
        c = tp.compile_pack(p)
        self.assertTrue(c["hash"].startswith("sha256:"))
        self.assertEqual(c["hash"], tp.pack_hash({k: v for k, v in c.items() if k != "hash"}))

    def test_invalid(self):
        self.assertTrue(tp.validate_pack({"version": 1, "steps": [{"type": "load"}]}))  # no id
        self.assertTrue(tp.validate_pack({"id": "x", "version": 1, "steps": []}))       # no steps
        self.assertTrue(any("unknown type" in e for e in
                            tp.validate_pack({"id": "x", "version": 1, "steps": [{"type": "bogus"}]})))
        self.assertTrue(any("requires 'dataset'" in e for e in
                            tp.validate_pack({"id": "x", "version": 1, "steps": [{"type": "invoke"}]})))

    def test_matches(self):
        llm = tp.BUILTIN_PACKS["llm-basic"]
        self.assertTrue(tp.matches(llm, artifact_kind="llm-safetensors", engine="harbor/engine-vllm@sha256:" + "a" * 64))
        self.assertFalse(tp.matches(llm, artifact_kind="pickle", engine="kind:llm"))
        fmt = tp.BUILTIN_PACKS["format-basic"]
        self.assertTrue(tp.matches(fmt, artifact_kind="safetensors"))
        self.assertFalse(tp.matches(fmt, artifact_kind="llm-gguf"))

    def test_select_and_builtin_compile(self):
        packs = tp.all_builtin()
        for p in packs:
            self.assertEqual(tp.validate_pack(p), [])
        sel = tp.select_packs(packs, artifact_kind="pickle", engine="kind:llm")
        self.assertIn("code-exec-basic", [p["id"] for p in sel])

    def test_fail_fast_compile(self):
        with self.assertRaises(ValueError):
            tp.compile_pack({"id": "x", "version": 1, "steps": [{"type": "stream"}]})


class DatasetTest(unittest.TestCase):
    def test_parse_ref(self):
        r = ds.parse_ref("ds://prompts/redteam-ru@4")
        self.assertEqual((r["kind"], r["name"], r["version"]), ("prompts", "redteam-ru", 4))
        with self.assertRaises(ValueError):
            ds.parse_ref("prompts/x")
        self.assertEqual(ds.make_ref("prompts", "a", 2), "ds://prompts/a@2")

    def test_repo(self):
        repo = ds.DatasetRepo()
        repo.register("ds://prompts/benign@1", [{"id": 1, "prompt": "hi"}])
        self.assertEqual(len(repo.fetch("ds://prompts/benign@1")), 1)
        self.assertEqual(len(repo.fetch("ds://prompts/benign@9")), 1)  # версия-независимо
        self.assertEqual(repo.fetch("ds://prompts/missing@1"), [])
        refs = repo.list_refs()
        self.assertEqual(refs[0]["cases"], 1)
        self.assertTrue(refs[0]["hash"].startswith("sha256:"))


if __name__ == "__main__":
    unittest.main()
