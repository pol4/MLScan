#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v4: unit-тесты in-job probe и engine client (HTTP на localhost)."""
from __future__ import annotations

import json
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "deploy", "v4"))

import tests.probe as probe                    # noqa: E402
from tests.engine_client import EngineClient   # noqa: E402


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # noqa: A003
        pass

    def do_GET(self):  # noqa: N802
        if self.path.endswith("/models"):
            self._send({"data": [{"id": "m"}]})
        else:
            self._send({}, code=404)

    def do_POST(self):  # noqa: N802
        n = int(self.headers.get("Content-Length", 0) or 0)
        _ = self.rfile.read(n)
        self._send({"choices": [{"message": {"content": "Извините, не могу помочь."}}],
                    "usage": {"completion_tokens": 3}})

    def _send(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class ProbeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), _Handler)
        cls.url = f"http://127.0.0.1:{cls.srv.server_port}"
        cls.t = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.t.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_engine_client(self):
        c = EngineClient(base=self.url, wait_s=2)
        self.assertTrue(c.health(tries=2))
        out = c.invoke({"prompt": "hi", "params": {"max_tokens": 8}})
        self.assertIn("не могу", out["text"])
        self.assertEqual(out["usage"]["completion_tokens"], 3)

    def test_build_plan(self):
        env = {"testpack": {"id": "llm-basic", "version": 2}}
        p = probe.build_plan([{"id": 1, "prompt": "x"}], env, 64)
        self.assertEqual(p["id"], "llm-basic")
        self.assertEqual([s["type"] for s in p["steps"]], ["load", "invoke", "assert"])
        self.assertEqual(p["datasets"][0]["ref"], "ds://prompts/active@1")

    def test_build_score_payload(self):
        cases = [{"id": 1, "prompt": "x"}, {"id": 2, "prompt": "y"}]
        result = {"responses": [{"id": 1, "text": "a"}, {"id": 2, "text": "b"}],
                  "budgets_used": {"tokens": 10}}
        payload = probe.build_score_payload(cases, result, {"testpack": {"id": "t"}}, 1.5)
        self.assertEqual(payload["responses"], {"1": ["a"], "2": ["b"]})
        self.assertEqual(payload["metrics"]["questions"], 2)
        self.assertEqual(payload["metrics"]["completion_tokens"], 10)
        self.assertEqual(payload["testpack"], {"id": "t"})


if __name__ == "__main__":
    unittest.main()
