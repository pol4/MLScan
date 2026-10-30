#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Юнит-тесты HDF5-адаптера потоковой статики (B8)."""
import os
import pickle
import struct
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "deploy", "v3", "analysis"))
import static_stream  # noqa: E402

HDF5_SIG = b"\x89HDF\r\n\x1a\n"


def reader_for(blob: bytes):
    def reader(offset: int, length: int) -> bytes:
        return blob[offset:offset + length]
    return reader


def sb(ver: int = 0, tail: bytes = b"") -> bytes:
    """Минимальный «суперблок»: сигнатура + версия + произвольный хвост."""
    return HDF5_SIG + bytes([ver]) + b"\x00" * 7 + tail


class Hdf5StaticTest(unittest.TestCase):
    def test_bad_signature(self):
        out = static_stream.analyze_hdf5(reader_for(b"not-an-hdf5-file" * 100), 1700)
        self.assertFalse(out["coverage"]["index"])
        self.assertEqual(out["findings"][0]["check_id"], "FMT-H5-01")

    def test_clean_hdf5(self):
        blob = sb(0, b"some dataset payload without pickles")
        out = static_stream.analyze_hdf5(reader_for(blob), len(blob))
        self.assertTrue(out["coverage"]["index"])
        self.assertEqual(out["details"]["superblock_version"], 0)
        self.assertEqual(out["findings"], [])

    def test_userblock_offset(self):
        blob = b"\x00" * 512 + sb(0, b"data")
        out = static_stream.analyze_hdf5(reader_for(blob), len(blob))
        self.assertTrue(out["coverage"]["index"])
        self.assertEqual(out["details"]["superblock_offset"], 512)

    def test_embedded_pickle_dangerous_global(self):
        evil = pickle.dumps({"f": eval}, protocol=4)          # GLOBAL builtins eval в потоке
        blob = sb(0, b"attrs" + evil + b"tail")
        out = static_stream.analyze_hdf5(reader_for(blob), len(blob))
        ids = [f["check_id"] for f in out["findings"]]
        self.assertIn("FMT-H5-02", ids)
        self.assertGreaterEqual(out["details"]["pickle_streams"], 1)

    def test_embedded_pickle_without_dangerous(self):
        data = pickle.dumps({"a": 1}, protocol=2)
        blob = sb(0, b"attrs" + data)
        out = static_stream.analyze_hdf5(reader_for(blob), len(blob))
        ids = [f["check_id"] for f in out["findings"]]
        self.assertIn("FMT-H5-03", ids)
        self.assertNotIn("FMT-H5-02", ids)

    def test_external_refs_hint(self):
        blob = sb(0, b"external _refs link to /other/file")
        out = static_stream.analyze_hdf5(reader_for(blob), len(blob))
        self.assertTrue(out["details"].get("has_external_refs"))

    def test_dispatch_by_format(self):
        blob = sb(0, b"x")
        for fmt in ("hdf5", "h5", "keras"):
            out = static_stream.analyze(reader_for(blob), len(blob), fmt=fmt)
            self.assertEqual(out["format"], "hdf5")


if __name__ == "__main__":
    unittest.main(verbosity=2)
