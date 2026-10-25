#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Модульные тесты multipart-загрузки s3client (этап P0-1, docs/15 §11.6).

Запуск:  python3 -m unittest discover -s tests/s3 -v
"""
from __future__ import annotations

import hashlib
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), "deploy", "v2", "data", "s3"))

from fake_s3 import ACCESS, SECRET, FakeS3Server  # noqa: E402
from s3client import S3  # noqa: E402


class MultipartTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = FakeS3Server()
        cls.srv.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.srv.__exit__(None, None, None)

    def make(self) -> S3:
        return S3(self.srv.endpoint, ACCESS, SECRET, region="garage", bucket="mlscan-artifacts")

    def test_create_upload_complete_roundtrip(self):
        s3 = self.make()
        body = b"".join(os.urandom(4096) for _ in range(8))
        uid = s3.create_multipart("k/roundtrip.bin")
        self.assertTrue(uid)
        etags = []
        for i in range(1, 5):
            chunk = body[(i - 1) * 8192:i * 8192]
            et = s3.upload_part("k/roundtrip.bin", uid, i, chunk)
            self.assertEqual(et, hashlib.md5(chunk).hexdigest())
            etags.append((i, et))
        st, _, _ = s3.complete_multipart("k/roundtrip.bin", uid, etags)
        self.assertEqual(st, 200)
        st, _, got = s3.get("k/roundtrip.bin")
        self.assertEqual(st, 200)
        self.assertEqual(got, body)

    def test_upload_part_stream(self):
        s3 = self.make()
        body = os.urandom(9000)
        tmp = tempfile.NamedTemporaryFile(delete=False)
        tmp.write(body)
        tmp.close()
        uid = s3.create_multipart("s.bin")
        etags = []
        with open(tmp.name, "rb") as fh:
            i = 1
            while True:
                chunk = fh.read(4000)
                if not chunk:
                    break
                etags.append((i, s3.upload_part("s.bin", uid, i, chunk)))
                i += 1
        s3.complete_multipart("s.bin", uid, etags)
        st, _, got = s3.get("s.bin")
        self.assertEqual(st, 200)
        self.assertEqual(got, body)
        os.unlink(tmp.name)

    def test_put_file_multipart_roundtrip_and_sha(self):
        s3 = self.make()
        body = os.urandom(100_000)
        tmp = tempfile.NamedTemporaryFile(delete=False)
        tmp.write(body)
        tmp.close()
        res = s3.put_file_multipart("big/model.bin", tmp.name, part_size=16_384, workers=4)
        self.assertEqual(res["status"], 200)
        self.assertTrue(res["multipart"])
        self.assertEqual(res["size"], len(body))
        self.assertEqual(res["sha256"], hashlib.sha256(body).hexdigest())
        self.assertGreaterEqual(res["parts"], 6)
        st, _, got = s3.get("big/model.bin")
        self.assertEqual(got, body)
        self.assertTrue(s3.exists("big/model.bin"))
        os.unlink(tmp.name)

    def test_put_stream_multipart_parallel_order(self):
        s3 = self.make()
        body = os.urandom(64_000)
        tmp = tempfile.NamedTemporaryFile(delete=False)
        tmp.write(body)
        tmp.close()
        sha = hashlib.sha256(body).hexdigest()
        with open(tmp.name, "rb") as fh:
            res = s3.put_stream_multipart("par/model.bin", fh, len(body), sha,
                                          part_size=7_000, workers=8)
        self.assertEqual(res["status"], 200)
        self.assertEqual(res["sha256"], sha)
        st, _, got = s3.get("par/model.bin")
        self.assertEqual(got, body, "order of parallel parts must be preserved")
        os.unlink(tmp.name)

    def test_list_parts_for_resume(self):
        s3 = self.make()
        uid = s3.create_multipart("res.bin")
        s3.upload_part("res.bin", uid, 1, b"aaaa")
        s3.upload_part("res.bin", uid, 2, b"bbbb")
        parts = dict(s3.list_parts("res.bin", uid))
        self.assertEqual(sorted(parts), [1, 2])
        self.assertEqual(parts[1], hashlib.md5(b"aaaa").hexdigest())

    def test_abort(self):
        s3 = self.make()
        uid = s3.create_multipart("abort.bin")
        s3.upload_part("abort.bin", uid, 1, b"xx")
        st, _, _ = s3.abort_multipart("abort.bin", uid)
        self.assertIn(st, (200, 204))
        self.assertFalse(s3.exists("abort.bin"))

    def test_complete_rejects_missing_part_etag(self):
        s3 = self.make()
        uid = s3.create_multipart("bad.bin")
        s3.upload_part("bad.bin", uid, 1, b"aaaa")
        st, _, _ = s3.complete_multipart("bad.bin", uid, [(1, "deadbeefdeadbeefdeadbeefdeadbeef")])
        self.assertGreaterEqual(st, 400)


class PresignTest(unittest.TestCase):
    """Проверки presigned-URL (P0-2): структура, подпись, публичный хост."""

    def _s3(self, public=""):
        return S3("http://127.0.0.1:3900", ACCESS, SECRET, region="garage",
                  bucket="mlscan-artifacts", public_endpoint=public)

    def test_presign_contains_signature_and_query(self):
        url = self._s3().presign_upload_part("k/model.bin", "UID123", 3)
        self.assertIn("X-Amz-Signature=", url)
        self.assertIn("X-Amz-Algorithm=AWS4-HMAC-SHA256", url)
        self.assertIn("partNumber=3", url)
        self.assertIn("uploadId=UID123", url)
        self.assertIn("/mlscan-artifacts/k/model.bin?", url)

    def test_presign_signature_matches_recompute(self):
        import hashlib as H
        import hmac as M
        import urllib.parse as UP
        s3 = self._s3()
        url = s3.presign_upload_part("k/x.bin", "U1", 1, expires=600)
        q = UP.parse_qsl(UP.urlsplit(url).query, keep_blank_values=True)
        qd = dict(q)
        sig_got = qd.pop("X-Amz-Signature")
        cq = "&".join(f"{UP.quote(k, safe='-_.~')}={UP.quote(v, safe='-_.~')}"
                      for k, v in sorted(qd.items()))
        path = "/mlscan-artifacts/k/x.bin"
        ch = f"host:{s3.pub_host}:{s3.pub_port}\n"
        creq = "\n".join(["PUT", path, cq, ch, "host", "UNSIGNED-PAYLOAD"])
        scope = qd["X-Amz-Credential"].split("/", 1)[1]
        sts = "\n".join(["AWS4-HMAC-SHA256", qd["X-Amz-Date"], scope,
                         H.sha256(creq.encode()).hexdigest()])
        ds = qd["X-Amz-Credential"].split("/")[1]
        key = M.new(("AWS4" + SECRET).encode(), ds.encode(), H.sha256).digest()
        for p in ("garage", "s3", "aws4_request"):
            key = M.new(key, p.encode(), H.sha256).digest()
        sig_want = M.new(key, sts.encode(), H.sha256).hexdigest()
        self.assertEqual(sig_got, sig_want)

    def test_presign_public_host_override(self):
        url = self._s3(public="http://s3.example.com:30900").presign_upload_part("k/y", "U", 2)
        self.assertTrue(url.startswith("http://s3.example.com:30900/"), url)


if __name__ == "__main__":
    unittest.main(verbosity=2)
