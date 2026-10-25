#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""P7: unit-тесты метрик (per-tenant), SLO-алёртов и capacity-модели."""
from __future__ import annotations

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "deploy", "v3", "obs"))

import metrics  # noqa: E402
import slo  # noqa: E402


class MetricsTest(unittest.TestCase):
    def test_counter_with_tenant_labels(self):
        r = metrics.Registry()
        r.inc("mlscan_v3_upload_bytes_total", {"tenant": "a"}, 100)
        r.inc("mlscan_v3_upload_bytes_total", {"tenant": "a"}, 50)
        r.inc("mlscan_v3_upload_bytes_total", {"tenant": "b"}, 10)
        self.assertEqual(r.get("mlscan_v3_upload_bytes_total", {"tenant": "a"}), 150)
        out = r.render()
        self.assertIn('mlscan_v3_upload_bytes_total{tenant="a"} 150', out)
        self.assertIn('mlscan_v3_upload_bytes_total{tenant="b"} 10', out)

    def test_gauge_overwrite(self):
        r = metrics.Registry()
        r.set("mlscan_v3_queue_depth", 5)
        r.set("mlscan_v3_queue_depth", 2)
        self.assertEqual(r.get("mlscan_v3_queue_depth", kind="gauge"), 2)
        self.assertIn("mlscan_v3_queue_depth 2", r.render())

    def test_histogram_lite(self):
        r = metrics.Registry()
        r.observe("mlscan_v3_static_seconds", 1.5)
        r.observe("mlscan_v3_static_seconds", 2.5)
        out = r.render()
        self.assertIn("mlscan_v3_static_seconds_count 2", out)
        self.assertIn("mlscan_v3_static_seconds_sum 4.0", out)


class SloTest(unittest.TestCase):
    def test_no_alerts(self):
        self.assertEqual(slo.evaluate({"ingest_gbps": 2.0, "static_seconds": 100,
                                       "coverage_ratio": 0.99, "inconclusive_ratio": 0.05,
                                       "dynamic_fail_rate": 0.01}), [])

    def test_ingest_below_floor(self):
        a = slo.evaluate({"ingest_gbps": 0.3})
        self.assertEqual(a[0]["alert"], "ingest_below_floor")

    def test_coverage_and_inconclusive(self):
        ids = {x["alert"] for x in slo.evaluate({"coverage_ratio": 0.5, "inconclusive_ratio": 0.5})}
        self.assertIn("coverage_low", ids); self.assertIn("inconclusive_high", ids)

    def test_dynamic_critical(self):
        a = slo.evaluate({"dynamic_fail_rate": 0.5})
        self.assertEqual(a[0]["severity"], "critical")

    def test_static_archive_slow(self):
        ids = {x["alert"] for x in slo.evaluate({"static_seconds": 10000, "archive_seconds": 20000})}
        self.assertIn("static_slow", ids); self.assertIn("archive_slow", ids)


class CapacityTest(unittest.TestCase):
    def test_capacity_basic(self):
        c = slo.capacity(volume_bytes=10 ** 12, throughput_gbps=10.0)
        self.assertGreater(c["stored_bytes"], 10 ** 12)          # overhead 10%
        self.assertAlmostEqual(c["ingest_hours"], round((10 ** 12 * 8) / (10 * 1e9) / 3600, 2), places=1)

    def test_dedup_reduces_storage(self):
        a = slo.capacity(volume_bytes=10 ** 12, throughput_gbps=10.0, dedup_ratio=0.0)
        b = slo.capacity(volume_bytes=10 ** 12, throughput_gbps=10.0, dedup_ratio=0.5)
        self.assertLess(b["stored_bytes"], a["stored_bytes"])

    def test_nodes_for_target(self):
        c = slo.capacity(volume_bytes=10 ** 13, throughput_gbps=1.0, target_hours=24.0)
        self.assertGreaterEqual(c["nodes_for_target"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
