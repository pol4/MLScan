#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""P1-6: потоковый статический анализ по префиксу — эквивалентность полному файлу.

Проверяет, что статика по префиксу (с указанием реального размера) даёт те же
структурные находки для safetensors, что и анализ целого файла (нет ложных
срабатываний по header_len/границам тензоров).

Запуск:  python3 -m unittest discover -s tests/formats -v
"""
from __future__ import annotations

import json
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "poc"))
import mlscan_poc  # noqa: E402


def _make_safetensors(path: str, n_floats: int) -> int:
    header = {"w": {"dtype": "F32", "shape": [n_floats], "data_offsets": [0, n_floats * 4]}}
    hj = json.dumps(header).encode()
    with open(path, "wb") as fh:
        fh.write(struct.pack("<Q", len(hj)))
        fh.write(hj)
        fh.write(b"\x00" * (n_floats * 4))   # нули: без NaN/Inf
    return os.path.getsize(path)


def _findings_key(res):
    return sorted((f.get("check_id"), f.get("title")) for f in res.get("findings", []))


class PrefixStaticTest(unittest.TestCase):
    def test_prefix_matches_full_safetensors(self):
        n = 2_000_000          # ~8 МБ данных
        with tempfile.TemporaryDirectory() as d:
            full = os.path.join(d, "model.safetensors")
            size = _make_safetensors(full, n)
            with open(full, "rb") as fh:
                prefix_bytes = fh.read(1024 * 1024)
            pfx = os.path.join(d, "model_pfx.safetensors")  # тот же суффикс для детекции
            with open(pfx, "wb") as fh:
                fh.write(prefix_bytes)

            res_full = mlscan_poc.static_stage(Path(full))
            res_pfx = mlscan_poc.static_stage(Path(pfx), total_size=size)

            self.assertEqual(res_full.get("adapter_format"), "safetensors")
            self.assertEqual(res_pfx.get("adapter_format"), "safetensors")
            self.assertEqual(_findings_key(res_full), _findings_key(res_pfx),
                             "статика по префиксу должна совпадать с полным анализом")
            bad = [f for f in res_pfx.get("findings", []) if f.get("check_id") in ("FMT-01", "FMT-02")]
            self.assertEqual(bad, [], f"ложные срабатывания по границам: {bad}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
