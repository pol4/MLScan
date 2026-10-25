#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Мини-эмулятор S3 с поддержкой Multipart Upload и проверкой SigV4.

Используется модульными тестами s3client (tests/s3/test_multipart.py):
реализует CreateMultipartUpload / UploadPart / CompleteMultipartUpload /
AbortMultipartUpload, GET/HEAD/DELETE, а также пересчитывает подпись SigV4
(включая канонический query-string) и отвечает 403 при расхождении.
"""
from __future__ import annotations

import hashlib
import hmac
import http.server
import socketserver
import threading
import urllib.parse
import xml.etree.ElementTree as ET

ACCESS = "testaccess"
SECRET = "testsecret"
REGION = "garage"


def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def _signing_key(secret: str, datestamp: str, region: str) -> bytes:
    k = _sign(("AWS4" + secret).encode(), datestamp)
    k = _sign(k, region)
    k = _sign(k, "s3")
    return _sign(k, "aws4_request")


def _enc(s: str) -> str:
    return urllib.parse.quote(s, safe="-_.~")


def canonical_query(query_pairs) -> str:
    pairs = sorted((k, "" if v is None else v) for k, v in query_pairs)
    return "&".join(f"{_enc(k)}={_enc(v)}" for k, v in pairs)


class _Store:
    def __init__(self):
        self.lock = threading.Lock()
        self.uploads = {}   # upload_id -> {"key":..., "parts": {n: bytes}}
        self.objects = {}   # key -> bytes
        self.aborted = set()
        self.fail_parts = 0  # сколько ближайших PUT-частей «упасть» (тест retry)


class MultipartS3(http.server.BaseHTTPRequestHandler):
    store = _Store()          # общий на сервер
    access = ACCESS
    secret = SECRET
    region = REGION

    def log_message(self, *a):  # тишина в тестах
        pass

    # --- разбор запроса -------------------------------------------------
    def _split(self):
        u = urllib.parse.urlsplit(self.path)
        pairs = urllib.parse.parse_qsl(u.query, keep_blank_values=True)
        return u.path, pairs

    def _read_body(self) -> bytes:
        n = int(self.headers.get("Content-Length", "0") or "0")
        return self.rfile.read(n) if n else b""

    def _verify(self, method: str, path: str, qpairs, payload_hash: str) -> bool:
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("AWS4-HMAC-SHA256 "):
            return False
        try:
            kv = dict(p.strip().split("=", 1) for p in auth[len("AWS4-HMAC-SHA256 "):].split(","))
            cred = kv["Credential"]
            signed_headers = kv["SignedHeaders"]
            signature = kv["Signature"]
        except Exception:
            return False
        access, datestamp, region, _, _ = cred.split("/")
        if access != self.access:
            return False
        hdrs = {h: self.headers.get(h, "") for h in signed_headers.split(";")}
        canonical_headers = "".join(f"{h}:{hdrs[h]}\n" for h in signed_headers.split(";"))
        cq = canonical_query(qpairs)
        creq = "\n".join([method, path, cq, canonical_headers, signed_headers, payload_hash])
        scope = f"{datestamp}/{region}/s3/aws4_request"
        sts = "\n".join(["AWS4-HMAC-SHA256", self.headers.get("x-amz-date", ""), scope,
                         hashlib.sha256(creq.encode()).hexdigest()])
        sig = hmac.new(_signing_key(self.secret, datestamp, region), sts.encode(),
                       hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig, signature)

    def _deny(self):
        self.send_response(403)
        self.end_headers()
        self.wfile.write(b"<Error><Code>SignatureDoesNotMatch</Code></Error>")

    def _xml(self, code, body: bytes, etag: str | None = None):
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        if etag:
            self.send_header("ETag", f'"{etag}"')
        self.send_header("Content-Type", "application/xml")
        self.end_headers()
        self.wfile.write(body)

    # --- методы ---------------------------------------------------------
    def do_POST(self):
        path, qpairs = self._split()
        body = self._read_body()
        ph = self.headers.get("x-amz-content-sha256", hashlib.sha256(body).hexdigest())
        if not self._verify("POST", path, qpairs, ph):
            return self._deny()
        q = dict(qpairs)
        if "uploads" in q:
            uid = hashlib.sha256(f"{path}{self.store.lock}".encode()).hexdigest()[:24]
            with self.store.lock:
                self.store.uploads[uid] = {"key": path, "parts": {}}
            xml = (f"<?xml version='1.0'?><InitiateMultipartUploadResult>"
                   f"<Bucket>b</Bucket><Key>{path}</Key><UploadId>{uid}</UploadId>"
                   f"</InitiateMultipartUploadResult>").encode()
            return self._xml(200, xml)
        if "uploadId" in q:
            uid = q["uploadId"]
            with self.store.lock:
                up = self.store.uploads.get(uid)
            if not up:
                return self._xml(404, b"<Error><Code>NoSuchUpload</Code></Error>")
            root = ET.fromstring(body)
            parts = []
            for p in root.findall(".//Part"):
                parts.append((int(p.findtext("PartNumber")), p.findtext("ETag").strip('"')))
            with self.store.lock:
                data = b""
                for n, et in sorted(parts):
                    chunk = up["parts"].get(n)
                    if chunk is None or hashlib.md5(chunk).hexdigest() != et:
                        return self._xml(400, b"<Error><Code>BadDigest</Code></Error>")
                    data += chunk
                self.store.objects[up["key"]] = data
            etag = hashlib.md5(data).hexdigest()
            xml = (f"<?xml version='1.0'?><CompleteMultipartUploadResult><ETag>&quot;{etag}&quot;"
                   f"</ETag></CompleteMultipartUploadResult>").encode()
            return self._xml(200, xml)
        return self._xml(400, b"<Error><Code>BadRequest</Code></Error>")

    def do_PUT(self):
        path, qpairs = self._split()
        body = self._read_body()
        ph = self.headers.get("x-amz-content-sha256", hashlib.sha256(body).hexdigest())
        if not self._verify("PUT", path, qpairs, ph):
            return self._deny()
        q = dict(qpairs)
        if "partNumber" in q and "uploadId" in q:
            uid, n = q["uploadId"], int(q["partNumber"])
            with self.store.lock:
                if self.store.fail_parts > 0:
                    self.store.fail_parts -= 1
                    return self._xml(503, b"<Error><Code>SlowDown</Code></Error>")
                up = self.store.uploads.get(uid)
                if not up:
                    return self._xml(404, b"<Error><Code>NoSuchUpload</Code></Error>")
                up["parts"][n] = body
            return self._xml(200, b"", etag=hashlib.md5(body).hexdigest())
        with self.store.lock:
            self.store.objects[path] = body
        return self._xml(200, b"", etag=hashlib.md5(body).hexdigest())

    def do_DELETE(self):
        path, qpairs = self._split()
        if not self._verify("DELETE", path, qpairs, hashlib.sha256(b"").hexdigest()):
            return self._deny()
        q = dict(qpairs)
        if "uploadId" in q:
            with self.store.lock:
                self.store.uploads.pop(q["uploadId"], None)
                self.store.aborted.add(q["uploadId"])
            return self._xml(204, b"")
        with self.store.lock:
            self.store.objects.pop(path, None)
        return self._xml(204, b"")

    def do_HEAD(self):
        path, qpairs = self._split()
        if not self._verify("HEAD", path, qpairs, hashlib.sha256(b"").hexdigest()):
            return self._deny()
        with self.store.lock:
            obj = self.store.objects.get(path)
        if obj is None:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(obj)))
        self.send_header("ETag", f'"{hashlib.md5(obj).hexdigest()}"')
        self.end_headers()

    def do_GET(self):
        path, qpairs = self._split()
        if not self._verify("GET", path, qpairs, hashlib.sha256(b"").hexdigest()):
            return self._deny()
        q = dict(qpairs)
        if "uploadId" in q:
            with self.store.lock:
                up = self.store.uploads.get(q["uploadId"])
            if not up:
                return self._xml(404, b"<Error><Code>NoSuchUpload</Code></Error>")
            rows = ""
            for n in sorted(up["parts"]):
                et = hashlib.md5(up["parts"][n]).hexdigest()
                rows += (f"<Part><PartNumber>{n}</PartNumber><ETag>&quot;{et}&quot;</ETag>"
                         f"<Size>{len(up['parts'][n])}</Size></Part>")
            xml = (f"<?xml version='1.0'?><ListPartsResult><UploadId>{q['uploadId']}</UploadId>"
                   f"{rows}</ListPartsResult>").encode()
            return self._xml(200, xml)
        with self.store.lock:
            obj = self.store.objects.get(path)
        if obj is None:
            self.send_response(404)
            self.end_headers()
            return
        rng = self.headers.get("Range") or self.headers.get("range")
        if rng and rng.startswith("bytes="):
            spec = rng[len("bytes="):].split(",")[0].strip()
            a, _, b = spec.partition("-")
            start = int(a) if a else 0
            if b:
                end = int(b)
            else:
                end = len(obj) - 1
            end = min(end, len(obj) - 1)
            if start > end or start >= len(obj):
                self.send_response(416)
                self.send_header("Content-Range", f"bytes */{len(obj)}")
                self.end_headers()
                return
            chunk = obj[start:end + 1]
            self.send_response(206)
            self.send_header("Content-Length", str(len(chunk)))
            self.send_header("Content-Range", f"bytes {start}-{end}/{len(obj)}")
            self.end_headers()
            self.wfile.write(chunk)
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(obj)))
        self.end_headers()
        self.wfile.write(obj)


class FakeS3Server:
    """Запускает эмулятор S3 на свободном порту в отдельном потоке."""

    def __init__(self):
        MultipartS3.store = _Store()
        self.httpd = socketserver.ThreadingTCPServer(("127.0.0.1", 0), MultipartS3)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()

    @property
    def endpoint(self):
        return f"http://127.0.0.1:{self.port}"
