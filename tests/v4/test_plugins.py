#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v4: unit-тесты плагинов-зондов."""
from __future__ import annotations

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "deploy", "v4"))

import tests.plugins as plugins   # noqa: E402


class PluginsTest(unittest.TestCase):
    def test_builtin_introspect(self):
        self.assertIn("introspect", plugins.names())
        out = plugins.run("introspect", {"engine": "vllm", "engine_manifest": {"id": "vllm-0.9.2"}})
        self.assertEqual(out[0]["id"], "PROBE-INTROSPECT")
        self.assertEqual(out[0]["severity"], "info")

    def test_unknown_plugin(self):
        self.assertEqual(plugins.run("nope", {}), [])

    def test_register_and_error(self):
        @plugins.register("boom")
        def _boom(ctx):
            raise RuntimeError("x")
        out = plugins.run("boom", {})
        self.assertEqual(out[0]["id"], "PLUGIN-boom")
        self.assertIn("error", out[0]["evidence"])

    def test_run_ctx(self):
        @plugins.register("emit")
        def _emit(ctx):
            return [{"id": "PL-1", "severity": "high", "category": "probe"}]
        out = plugins.run("emit", {"engine": "e"})
        self.assertEqual(out[0]["id"], "PL-1")


if __name__ == "__main__":
    unittest.main()
