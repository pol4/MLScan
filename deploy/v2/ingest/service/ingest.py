#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MLScan Ingest Gateway (I1): потоковый приём моделей и загрузка в S3 (content-addressed).

Только stdlib. Артефакт читается чанками во временный файл (emptyDir на быстром диске),
sha256 считается «на лету», затем объект кладётся в S3 по ключу <sha256>/<name> (дедуп по HEAD).

API:
  POST /uploads?name=&fmt=   потоковая загрузка -> 202 {sha256,size,key,dedup}
  GET  /objects/<sha256>/<name>   потоковая выдача объекта из S3
  GET  /uploads              список загрузок (в памяти)
  GET  /stats                агрегаты (кол-во, байты, дедуп)
  GET  /healthz
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
import time
import uuid
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, "/opt/s3")
from s3client import S3  # noqa: E402

S3_ENDPOINT = os.environ["S3_ENDPOINT"]
S3_REGION = os.environ.get("S3_REGION", "garage")
S3_BUCKET = os.environ["S3_BUCKET"]
S3_ACCESS = os.environ["S3_ACCESS_KEY"]
S3_SECRET = os.environ["S3_SECRET_KEY"]
DATA_TMP = os.environ.get("DATA_TMP", "/var/tmp")
MAX_UPLOAD = int(os.environ.get("MAX_UPLOAD", str(1 << 40)))  # 1 TiB

_s3 = S3(S3_ENDPOINT, S3_ACCESS, S3_SECRET, region=S3_REGION, bucket=S3_BUCKET, timeout=3600)
_lock = threading.Lock()
_uploads: dict[str, dict] = {}
_stats = {"uploads": 0, "bytes": 0, "dedup": 0, "objects": 0}


class Handler(BaseHTTPRequestHandler):
    server_version = "MLScanIngest/0.1"

    def log_message(self, *a):
        pass

    def _json(self, code: int, obj) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        u = urllib.parse.urlparse(self.path)
        if u.path == "/healthz":
            return self._json(200, {"status": "ok", "bucket": S3_BUCKET})
        if u.path == "/stats":
            with _lock:
                return self._json(200, dict(_stats, uploads_listed=len(_uploads)))
        if u.path == "/uploads":
            with _lock:
                return self._json(200, {"uploads": list(_uploads.values())})
        if u.path.startswith("/objects/"):
            rest = u.path[len("/objects/"):]
            sha, _, name = rest.partition("/")
            key = f"{sha}/{urllib.parse.unquote(name)}"
            try:
                status, headers, resp = _s3.get_stream(key)
            except Exception as exc:  # noqa: BLE001
                return self._json(502, {"error": f"s3: {exc}"})
            if status != 200:
                return self._json(status, {"error": f"s3 status {status}"})
            self.send_response(200)
            cl = headers.get("Content-Length")
            if cl:
                self.send_header("Content-Length", cl)
            self.send_header("Content-Type", headers.get("Content-Type", "application/octet-stream"))
            self.end_headers()
            while True:
                chunk = resp.read(1 << 20)
                if not chunk:
                    break
                self.wfile.write(chunk)
            return
        return self._json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        u = urllib.parse.urlparse(self.path)
        if u.path not in ("/uploads", "/scans/upload", "/upload"):
            return self._json(404, {"error": "not found"})
        q = urllib.parse.parse_qs(u.query)
        name = os.path.basename(q.get("name", ["sample.bin"])[0]) or "sample.bin"
        fmt = q.get("fmt", ["pickle"])[0]
        n = int(self.headers.get("Content-Length", "0") or "0")
        if n <= 0:
            return self._json(400, {"error": "empty body (нужен Content-Length)"})
        if n > MAX_UPLOAD:
            return self._json(413, {"error": f"too large ({n} > {MAX_UPLOAD})"})
        os.makedirs(DATA_TMP, exist_ok=True)
        tmp = os.path.join(DATA_TMP, "up-" + uuid.uuid4().hex)
        h = hashlib.sha256()
        got = 0
        t0 = time.monotonic()
        with open(tmp, "wb") as fh:
            while got < n:
                chunk = self.rfile.read(min(1 << 20, n - got))
                if not chunk:
                    break
                fh.write(chunk)
                h.update(chunk)
                got += len(chunk)
        sha = h.hexdigest()
        key = f"{sha}/{name}"
        dedup = False
        try:
            dedup = _s3.exists(key)
            if not dedup:
                with open(tmp, "rb") as fh:
                    st, _, _ = _s3.put_stream(key, fh, got, sha, "application/octet-stream")
                if st not in (200, 201):
                    raise RuntimeError(f"s3 put status {st}")
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        dur = round(time.monotonic() - t0, 3)
        upid = uuid.uuid4().hex
        rec = {"upload_id": upid, "sha256": sha, "size": got, "key": key,
               "name": name, "format": fmt, "dedup": dedup, "seconds": dur,
               "mbps": round((got / 1048576) / dur, 1) if dur else None,
               "created": time.strftime("%Y-%m-%dT%H:%M:%S")}
        with _lock:
            _uploads[upid] = rec
            _stats["uploads"] += 1
            _stats["bytes"] += got
            if dedup:
                _stats["dedup"] += 1
            else:
                _stats["objects"] += 1
        return self._json(202, rec)


def main() -> None:
    os.makedirs(DATA_TMP, exist_ok=True)
    port = int(os.environ.get("PORT", "8080"))
    print(f"[ingest] :{port} bucket={S3_BUCKET} tmp={DATA_TMP} max={MAX_UPLOAD}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()


if __name__ == "__main__":
    main()
