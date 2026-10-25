#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""L2: unit-тесты маппинга событий eBPF/Tetragon в findings (LLM-B-*)."""
from __future__ import annotations

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "deploy", "v3", "llm"))

import tetragon  # noqa: E402


def ev(**kw):
    base = {"nonce": "N1", "phase": "probe"}
    base.update(kw)
    return base


class TetragonTest(unittest.TestCase):
    def test_shell_exec(self):
        f, rej = tetragon.map_findings([ev(type="process_exec", process={"binary": "/bin/sh"})], "N1")
        self.assertEqual([x["check_id"] for x in f], ["LLM-B-01"])
        self.assertEqual(rej, 0)

    def test_shell_by_args(self):
        f, _ = tetragon.map_findings([ev(type="process_exec", process={"binary": "python3",
                                                                     "args": ["-c", "print(1)"]})], "N1")
        self.assertEqual(f[0]["check_id"], "LLM-B-01")

    def test_external_egress(self):
        f, _ = tetragon.map_findings([ev(type="network", dst={"ip": "8.8.8.8", "port": 443})], "N1")
        self.assertEqual(f[0]["check_id"], "LLM-B-02")

    def test_local_net_allowed(self):
        f, _ = tetragon.map_findings([ev(type="network", dst={"ip": "127.0.0.1", "port": 8000})], "N1")
        self.assertEqual(f, [])

    def test_honeypot_read(self):
        f, _ = tetragon.map_findings([ev(type="file", file={"path": "/root/.aws/credentials"})], "N1")
        self.assertEqual(f[0]["check_id"], "LLM-B-03")

    def test_memory_exec(self):
        f, _ = tetragon.map_findings([ev(type="memory", exec=True)], "N1")
        self.assertEqual(f[0]["check_id"], "LLM-B-04")

    def test_module_load(self):
        f, _ = tetragon.map_findings([ev(type="module")], "N1")
        self.assertEqual(f[0]["check_id"], "LLM-B-05")
        self.assertEqual(f[0]["severity"], "critical")

    def test_nonce_mismatch_rejected(self):
        f, rej = tetragon.map_findings([ev(type="process_exec", process={"binary": "sh"}, nonce="BAD")], "N1")
        self.assertEqual(f, [])
        self.assertEqual(rej, 1)

    def test_phase_and_probe_attached(self):
        f, _ = tetragon.map_findings([ev(type="network", dst={"ip": "1.2.3.4"}, phase="load", probe_id="p7")], "N1")
        self.assertEqual(f[0]["phase"], "load")
        self.assertEqual(f[0]["probe_id"], "p7")

    def test_max_severity(self):
        f, _ = tetragon.map_findings([ev(type="network", dst={"ip": "1.2.3.4"}),
                                      ev(type="module")], "N1")
        self.assertEqual(tetragon.max_severity(f), "critical")

    def test_unknown_ignored(self):
        f, _ = tetragon.map_findings([ev(type="syscall")], "N1")
        self.assertEqual(f, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
