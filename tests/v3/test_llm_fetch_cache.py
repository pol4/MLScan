#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v3/llm: unit-тесты G4 — кэш модели в model-fetcher (per-sha, staging+publish, lock).

Проверяет: загрузка идёт прямо в кэш (`<CACHE_DIR>/<key>.tmp/files`) и публикуется атомарно
(`.ready`, rename); повторный прогон берёт готовое (`CACHE_HIT`) без скачивания; staging в /model
не нужен (engine читает кэш через subPath). Скрипт fetcher'а исполняется как процесс.
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


def _read(p: str) -> bytes:
    with open(p, "rb") as fh:
        return fh.read()


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

    def _cachedir(self, key):
        return os.path.join(self.cache, key, "files")

    def test_dir_manifest_stage_and_publish(self):
        a = self._src("a.txt", b"alpha")
        b = self._src("sub/b.txt", b"beta-content")
        manifest = json.dumps([{"dest": "a.txt", "url": _file_url(a)},
                               {"dest": "sub/b.txt", "url": _file_url(b)}])
        key = "s" * 40
        r1 = self._run({"CACHE_DIR": self.cache, "CACHE_KEY": key, "FETCH_MANIFEST": manifest})
        self.assertEqual(r1.returncode, 0, r1.stderr)
        self.assertIn("FETCHED", r1.stdout)
        self.assertIn("CACHE_STORE", r1.stdout)
        self.assertTrue(os.path.exists(os.path.join(self.cache, key, ".ready")))
        self.assertFalse(os.path.exists(os.path.join(self.cache, key + ".tmp")))
        self.assertEqual(_read(os.path.join(self._cachedir(key), "a.txt")), b"alpha")
        self.assertEqual(_read(os.path.join(self._cachedir(key), "sub", "b.txt")), b"beta-content")
        # второй прогон — готовое, без скачивания
        r2 = self._run({"CACHE_DIR": self.cache, "CACHE_KEY": key, "FETCH_MANIFEST": manifest})
        self.assertEqual(r2.returncode, 0, r2.stderr)
        self.assertIn("CACHE_HIT", r2.stdout)
        self.assertNotIn("FETCHED", r2.stdout)

    def test_single_file_cache_and_sha(self):
        data = b"weights-only"
        sha = hashlib.sha256(data).hexdigest()
        src = self._src("m.gguf", data)
        key = "t" * 40
        r1 = self._run({"CACHE_DIR": self.cache, "CACHE_KEY": key,
                        "FETCH_URL": _file_url(src), "FETCH_SHA": sha})
        self.assertEqual(r1.returncode, 0, r1.stderr)
        self.assertIn("FETCHED", r1.stdout)
        self.assertEqual(_read(os.path.join(self._cachedir(key), "model.gguf")), data)
        r2 = self._run({"CACHE_DIR": self.cache, "CACHE_KEY": key,
                        "FETCH_URL": _file_url(src), "FETCH_SHA": sha})
        self.assertEqual(r2.returncode, 0, r2.stderr)
        self.assertIn("CACHE_HIT", r2.stdout)
        self.assertNotIn("FETCHED", r2.stdout)

    def test_sha_mismatch_fails(self):
        src = self._src("bad.gguf", b"x")
        r = self._run({"CACHE_DIR": self.cache, "CACHE_KEY": "u" * 40,
                       "FETCH_URL": _file_url(src), "FETCH_SHA": "0" * 64})
        self.assertEqual(r.returncode, 3)
        self.assertIn("SHA_MISMATCH", r.stdout)

    def test_no_cache_when_unset(self):
        src = self._src("p.txt", b"plain")
        work = os.path.join(self.root, "work")
        r = self._run({"MODEL_DIR": work,
                       "FETCH_MANIFEST": json.dumps([{"dest": "p.txt", "url": _file_url(src)}])})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("FETCHED", r.stdout)
        self.assertNotIn("CACHE_STORE", r.stdout)
        self.assertEqual(_read(os.path.join(work, "p.txt")), b"plain")

    def test_stale_lock_is_stolen(self):
        src = self._src("q.txt", b"qq")
        key = "v" * 40
        # протухший lock без .ready -> fetcher должен забрать lock и загрузить
        with open(os.path.join(self.cache, key + ".lock"), "w"):
            pass
        r = self._run({"CACHE_DIR": self.cache, "CACHE_KEY": key, "CACHE_LOCK_WAIT": "0",
                       "FETCH_MANIFEST": json.dumps([{"dest": "q.txt", "url": _file_url(src)}])})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("CACHE_STORE", r.stdout)
        self.assertTrue(os.path.exists(os.path.join(self.cache, key, ".ready")))

    def test_concurrent_waits_for_ready(self):
        src = self._src("r.txt", b"rr")
        key = "w" * 40
        # другой writer «держит» lock, но кэш уже готов -> ждать и взять без скачивания
        with open(os.path.join(self.cache, key + ".lock"), "w"):
            pass
        ready_dir = os.path.join(self.cache, key, "files")
        os.makedirs(ready_dir, exist_ok=True)
        with open(os.path.join(ready_dir, "r.txt"), "wb") as fh:
            fh.write(b"rr")
        with open(os.path.join(self.cache, key, ".ready"), "w"):
            pass
        r = self._run({"CACHE_DIR": self.cache, "CACHE_KEY": key, "CACHE_LOCK_WAIT": "5",
                       "FETCH_MANIFEST": json.dumps([{"dest": "r.txt", "url": _file_url(src)}])})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("CACHE_HIT", r.stdout)
        self.assertNotIn("FETCHED", r.stdout)


if __name__ == "__main__":
    unittest.main()
