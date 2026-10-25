#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""P0: unit-тесты общего пула (content-addressed) и ссылок тенантов (object_refs).

Запуск: python3 -m unittest discover -s tests/v3 -v
"""
from __future__ import annotations

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "deploy", "v3", "data"))

import objectrefs as refs  # noqa: E402
import pool  # noqa: E402

SHA = "ab" * 32


class PoolKeyTest(unittest.TestCase):
    def test_key_format_no_tenant(self):
        k = pool.pool_key(SHA)
        self.assertEqual(k, f"objects/ab/ab/{SHA}")
        self.assertNotIn("tenant", k)

    def test_validation(self):
        self.assertTrue(pool.is_sha256(SHA))
        for bad in ("", "xyz", SHA.upper(), SHA[:63], SHA + "0"):
            self.assertFalse(pool.is_sha256(bad))
            with self.assertRaises(ValueError):
                pool.pool_key(bad)

    def test_same_content_same_key(self):
        self.assertEqual(pool.pool_key(SHA), pool.pool_key(SHA))


class ObjectRefsTest(unittest.TestCase):
    def test_ddl_present(self):
        self.assertIn("CREATE TABLE IF NOT EXISTS object_refs", refs.DDL_OBJECT_REFS)
        self.assertIn("UNIQUE (tenant_id, sha256)", refs.DDL_OBJECT_REFS)

    def test_ref_add_upserts_and_increments(self):
        sql = refs.ref_add_sql("ci-team", SHA, name="m.bin", size=1024)
        self.assertIn("INSERT INTO object_refs", sql)
        self.assertIn("ON CONFLICT (tenant_id, sha256)", sql)
        self.assertIn("refcount = object_refs.refcount + 1", sql)
        self.assertIn("'ci-team'", sql)
        self.assertIn(f"'{SHA}'", sql)

    def test_ref_add_escapes_quotes(self):
        sql = refs.ref_add_sql("o'brien", SHA, name="a'b", size=1)
        self.assertIn("'o''brien'", sql)
        self.assertIn("'a''b'", sql)

    def test_ref_del_and_count(self):
        self.assertIn("refcount = refcount - 1", refs.ref_del_sql("t", SHA))
        self.assertIn("SUM(refcount)", refs.ref_count_sql(SHA))

    def test_validation(self):
        with self.assertRaises(ValueError):
            refs.ref_add_sql("", SHA)
        with self.assertRaises(ValueError):
            refs.ref_add_sql("t", "nothex")
        with self.assertRaises(ValueError):
            refs.ref_count_sql("bad")


if __name__ == "__main__":
    unittest.main(verbosity=2)
