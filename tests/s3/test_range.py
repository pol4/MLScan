#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""P0: unit-тесты Range-чтения s3client (анализ читает только нужные диапазоны).

Запуск: python3 -m unittest discover -s tests/s3 -v
"""
from __future__ import annotations

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "deploy", "v2", "data", "s3"))

from fake_s3 import ACCESS, SECRET, FakeS3Server  # noqa: E402
from s3client import S3  # noqa: E402


class RangeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = FakeS3Server()
        cls.srv.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.srv.__exit__(None, None, None)

    def make(self) -> S3:
        return S3(self.srv.endpoint, ACCESS, SECRET, region="garage", bucket="mlscan-artifacts")

    def test_range_middle(self):
        s3 = self.make()
        body = bytes(range(256)) * 40           # 10240 байт
        s3.put("k/model.bin", body)
        got = s3.range_get("k/model.bin", offset=1000, length=500)
        self.assertEqual(got, body[1000:1500])

    def test_range_head_and_open_ended(self):
        s3 = self.make()
        body = os.urandom(4096)
        s3.put("k/b.bin", body)
        self.assertEqual(s3.range_get("k/b.bin", 0, 16), body[:16])
        self.assertEqual(s3.range_get("k/b.bin", offset=4000), body[4000:])

    def test_range_beyond_end_clamped(self):
        s3 = self.make()
        body = os.urandom(100)
        s3.put("k/s.bin", body)
        self.assertEqual(s3.range_get("k/s.bin", 90, 1000), body[90:])

    def test_range_header_validation(self):
        s3 = self.make()
        with self.assertRaises(ValueError):
            s3.range_get("k/x", offset=-1)
        with self.assertRaises(ValueError):
            s3.range_get("k/x", offset=0, length=0)

    def test_range_stream(self):
        s3 = self.make()
        body = os.urandom(2048)
        s3.put("k/st.bin", body)
        st, hd, resp = s3.range_get_stream("k/st.bin", 512, 256)
        self.assertIn(st, (200, 206))
        self.assertEqual(resp.read(), body[512:768])
        resp.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
