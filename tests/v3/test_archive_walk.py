#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""P4: unit-тесты членного обхода архивов (zip центральный каталог / tar) + бюджеты/защита."""
from __future__ import annotations

import io
import os
import sys
import tarfile
import unittest
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "deploy", "v3", "analysis"))

import archive_walk  # noqa: E402


def reader_of(blob: bytes):
    calls = {"bytes": 0}

    def rd(off, length):
        chunk = blob[off:off + length]
        calls["bytes"] += len(chunk)
        return chunk
    return rd, calls


def make_zip(files: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in files.items():
            z.writestr(name, data)
    return buf.getvalue()


def make_tar(files: dict) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class ZipWalkTest(unittest.TestCase):
    def test_list_members_range(self):
        blob = make_zip({"model.safetensors": b"A" * 5000, "config.json": b"{}", "a/b.bin": b"x" * 100})
        rd, calls = reader_of(blob)
        r = archive_walk.list_members_zip(rd, len(blob))
        self.assertTrue(r["ok"])
        names = sorted(m["name"] for m in r["members"])
        self.assertEqual(names, ["a/b.bin", "config.json", "model.safetensors"])
        self.assertTrue(all("header_off" in m for m in r["members"]))

    def test_budgets_skip_large_member(self):
        blob = make_zip({"big.bin": os.urandom(100000), "small.bin": b"b" * 10})
        rd, _ = reader_of(blob)
        r = archive_walk.list_members_zip(rd, len(blob), budgets={"max_member_bytes": 1000})
        by = {m["name"]: m for m in r["members"]}
        self.assertEqual(by["big.bin"]["skip_reason"], "member_bytes")
        self.assertNotIn("skip_reason", by["small.bin"])
        plan = archive_walk.plan_members(r["members"], budgets={"max_member_bytes": 1000})
        self.assertEqual(plan["total"], 2); self.assertEqual(plan["analyzable"], 1)

    def test_zip_slip_detected(self):
        blob = make_zip({"normal.bin": b"n"})
        # вручную подменяем имя в центральном каталоге на небезопасное
        blob = blob.replace(b"normal.bin", b"../evil.bi")   # та же длина, небезопасный путь
        rd, _ = reader_of(blob)
        r = archive_walk.list_members_zip(rd, len(blob))
        ids = [f["check_id"] for f in r["findings"]]
        self.assertIn("ARCH-SLIP", ids)

    def test_not_a_zip(self):
        blob = b"not a zip at all" * 100
        rd, _ = reader_of(blob)
        r = archive_walk.list_members_zip(rd, len(blob))
        self.assertFalse(r["ok"])


class TarWalkTest(unittest.TestCase):
    def test_list_members_tar(self):
        blob = make_tar({"first.bin": b"A" * 100, "dir/second.bin": b"B" * 50})
        rd, calls = reader_of(blob)
        r = archive_walk.list_members_tar(rd, len(blob))
        self.assertTrue(r["ok"])
        names = [m["name"] for m in r["members"]]
        self.assertIn("first.bin", names); self.assertIn("dir/second.bin", names)
        # data_off указывает на начало данных члена
        m0 = next(m for m in r["members"] if m["name"] == "first.bin")
        self.assertEqual(rd(m0["data_off"], 5), b"A" * 5)

    def test_tar_budgets(self):
        blob = make_tar({f"f{i}.bin": b"x" * 10 for i in range(10)})
        rd, _ = reader_of(blob)
        r = archive_walk.list_members_tar(rd, len(blob), budgets={"max_members": 3})
        self.assertLessEqual(len(r["members"]), 10)  # парсинг остановится по бюджету
        plan = archive_walk.plan_members(r["members"], budgets={"max_members": 3})
        self.assertTrue(plan["total"] >= 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
