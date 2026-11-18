#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v3/llm: unit-тест G4 — кэш модели в model-fetcher (CACHE_DIR/CACHE_KEY).

Проверяет: загрузка кладёт модель в кэш (.ready), повторный прогон берёт её из кэша
(CACHE_HIT) без повторного скачивания — и для каталога модели (манифест), и для одного файла.
Скрипт fetcher'а исполняется как отдельный процесс с MODEL_DIR (подменяемый /model).
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "deploy", "v3", "llm"))

import llm_env as le  # noqa: E402


def _file_url(path: str) -> str:
    return "file://" + os.path.abspath(path)


class FetchCacheTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name
        self.script = os.path.join(self.root, "fetch.py")
        with open(self.script, "w", encoding="utf-8") as fh:
            fh.write(le._FETCH_SRC)
        self.cache = os.path.join(self.root, "cache")
        os.makedirs(self.cache, exist_ok=True)

    def _src(self, name, data):
        p = os.path.join(self.root, "src", name)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as fh:
            fh.write(data)
        return p

    def _run(self, env):
        base = dict(os.environ)
        base.update(env)
        return subprocess.run([sys.executable, self.script], env=base,
                              capture_output=True, text=True, timeout=120)

    def test_dir_manifest_cache_hit(self):
        a = self._src("a.txt", b"alpha")
        b = self._src("sub/b.txt", b"beta-content")
        manifest = json.dumps([{"dest": "a.txt", "url": _file_url(a)},
                               {"dest": "sub/b.txt", "url": _file_url(b)}])
        key = "s" * 40
        m1 = os.path.join(self.root, "m1")
        r1 = self._run({"MODEL_DIR": m1, "CACHE_DIR": self.cache, "CACHE_KEY": key,
                        "FETCH_MANIFEST": manifest})
        self.assertEqual(r1.returncode, 0, r1.stderr)
        self.assertIn("FETCHED", r1.stdout)
        self.assertIn("CACHE_STORE", r1.stdout)
        self.assertTrue(os.path.exists(os.path.join(self.cache, key, ".ready")))
        self.assertEqual(open(os.path.join(m1, "a.txt"), "rb").read(), b"alpha")
        self.assertEqual(open(os.path.join(m1, "sub", "b.txt"), "rb").read(), b"beta-content")
        # второй прогон — из кэша, без скачивания
        m2 = os.path.join(self.root, "m2")
        r2 = self._run({"MODEL_DIR": m2, "CACHE_DIR": self.cache, "CACHE_KEY": key,
                        "FETCH_MANIFEST": manifest})
        self.assertEqual(r2.returncode, 0, r2.stderr)
        self.assertIn("CACHE_HIT", r2.stdout)
        self.assertNotIn("FETCHED", r2.stdout)
        self.assertEqual(open(os.path.join(m2, "sub", "b.txt"), "rb").read(), b"beta-content")

    def test_single_file_cache_and_sha(self):
        data = b"weights-only"
        sha = hashlib.sha256(data).hexdigest()
        src = self._src("model.gguf", data)
        key = "t" * 40
        m1 = os.path.join(self.root, "s1")
        r1 = self._run({"MODEL_DIR": m1, "CACHE_DIR": self.cache, "CACHE_KEY": key,
                        "FETCH_URL": _file_url(src), "FETCH_SHA": sha})
        self.assertEqual(r1.returncode, 0, r1.stderr)
        self.assertIn("FETCHED", r1.stdout)
        self.assertTrue(os.path.exists(os.path.join(self.cache, key, ".ready")))
        self.assertEqual(open(os.path.join(m1, "model.gguf"), "rb").read(), data)
        m2 = os.path.join(self.root, "s2")
        r2 = self._run({"MODEL_DIR": m2, "CACHE_DIR": self.cache, "CACHE_KEY": key,
                        "FETCH_URL": _file_url(src), "FETCH_SHA": sha})
        self.assertEqual(r2.returncode, 0, r2.stderr)
        self.assertIn("CACHE_HIT", r2.stdout)
        self.assertEqual(open(os.path.join(m2, "model.gguf"), "rb").read(), data)

    def test_sha_mismatch_fails(self):
        src = self._src("bad.gguf", b"x")
        m = os.path.join(self.root, "b1")
        r = self._run({"MODEL_DIR": m, "FETCH_URL": _file_url(src), "FETCH_SHA": "0" * 64})
        self.assertEqual(r.returncode, 3)
        self.assertIn("SHA_MISMATCH", r.stdout)

    def test_no_cache_when_unset(self):
        src = self._src("p.txt", b"plain")
        m = os.path.join(self.root, "n1")
        r = self._run({"MODEL_DIR": m, "FETCH_MANIFEST": json.dumps([{"dest": "p.txt", "url": _file_url(src)}])})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("FETCHED", r.stdout)
        self.assertNotIn("CACHE_STORE", r.stdout)
        self.assertEqual(open(os.path.join(m, "p.txt"), "rb").read(), b"plain")


if __name__ == "__main__":
    unittest.main()
