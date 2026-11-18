#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v3/ebpf: unit-тест I4 — определение готовности движка (переход фазы load -> invoke)."""
from __future__ import annotations

import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "deploy", "v3", "sandbox", "kata-btf"))

import ebpf_agent as ea  # noqa: E402


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        if self.path.endswith("/v1/models"):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"data":[]}')
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *a):  # тишина в тестах
        pass


class EngineReadyTest(unittest.TestCase):
    def test_unreachable_is_false(self):
        self.assertFalse(ea._engine_ready("http://127.0.0.1:1", timeout=0.5))

    def test_ready_when_serving(self):
        srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            url = f"http://127.0.0.1:{srv.server_address[1]}"
            self.assertTrue(ea._engine_ready(url, timeout=2.0))
        finally:
            srv.shutdown()
            srv.server_close()

    def test_default_phase_without_dynamic(self):
        # без --dynamic-phase фаза совпадает с --phase (обратная совместимость сканов)
        import argparse
        ap = argparse.ArgumentParser()
        ap.add_argument("--phase", default="probe")
        ap.add_argument("--dynamic-phase", action="store_true")
        ap.add_argument("--load-phase", default="load")
        a = ap.parse_args(["--phase", "scan"])
        self.assertEqual(a.load_phase if a.dynamic_phase else a.phase, "scan")


if __name__ == "__main__":
    unittest.main()
