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

sys.path.insert(0, "/opt/auth")
try:
    import authz  # noqa: E402
except Exception:  # noqa: BLE001
    authz = None  # type: ignore

sys.path.insert(0, "/opt/i18n")
try:
    import i18n  # noqa: E402
except Exception:  # noqa: BLE001
    i18n = None  # type: ignore


def T(key: str, lang: str = "ru", **fmt) -> str:
    return i18n.t(key, lang, **fmt) if i18n else key

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

    def _lang(self, query: dict | None = None) -> str:
        if i18n is None:
            return "ru"
        raw = self.headers.get("Cookie", "") or ""
        cookie = ""
        for part in raw.split(";"):
            k, _, v = part.strip().partition("=")
            if k == "mlscan_lang":
                cookie = v
                break
        return i18n.resolve(headers=self.headers, query=query, cookie=cookie)

    def _require(self, allowed=None):
        if authz is None:
            return {"subject": "anonymous", "roles": ["admin"]}
        self._rid = authz.request_id(self.headers)
        ent = authz.authenticate(self.headers)
        if ent is None:
            self._subject = "anonymous"
            try:
                authz.audit("anonymous", "auth_denied", "http", self.path, self._rid,
                            self.client_address[0], {"method": self.command})
            except Exception:  # noqa: BLE001
                pass
            self._json(401, {"error": "unauthorized", "request_id": self._rid})
            return None
        if allowed and not (set(ent["roles"]) & set(allowed)):
            self._subject = ent["subject"]
            self._json(403, {"error": "forbidden", "request_id": self._rid})
            return None
        self._subject = ent["subject"]
        self._roles = ent.get("roles", [])
        return ent

    def _json(self, code: int, obj) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode()
        rid = getattr(self, "_rid", None)
        if rid is None and authz is not None:
            rid = authz.new_request_id()
            self._rid = rid
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if rid:
            self.send_header("X-Request-ID", rid)
        self.end_headers()
        self.wfile.write(body)
        if authz is not None and not getattr(self, "_logged", False):
            self._logged = True
            try:
                authz.log_connection(getattr(self, "_subject", "anonymous"), rid,
                                     self.client_address[0], self.headers.get("User-Agent", ""),
                                     self.path, self.command, code)
            except Exception:  # noqa: BLE001
                pass

    def do_GET(self) -> None:  # noqa: N802
        u = urllib.parse.urlparse(self.path)
        if u.path == "/healthz":
            return self._json(200, {"status": "ok", "bucket": S3_BUCKET})
        if self._require(["admin", "ci-reader", "service"]) is None:
            return
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
        return self._json(404, {"error": T("msg.not_found", self._lang())})

    def do_POST(self) -> None:  # noqa: N802
        u = urllib.parse.urlparse(self.path)
        if u.path not in ("/uploads", "/scans/upload", "/upload"):
            return self._json(404, {"error": T("msg.not_found", self._lang())})
        if self._require(["admin", "service"]) is None:
            return
        q = urllib.parse.parse_qs(u.query)
        name = os.path.basename(q.get("name", ["sample.bin"])[0]) or "sample.bin"
        fmt = q.get("fmt", ["pickle"])[0]
        n = int(self.headers.get("Content-Length", "0") or "0")
        if n <= 0:
            return self._json(400, {"error": T("msg.empty_body_cl", self._lang())})
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
        if authz is not None:
            try:
                authz.audit(getattr(self, "_subject", "anonymous"), "upload", "artifact", sha,
                            getattr(self, "_rid", upid), self.client_address[0],
                            {"name": name, "size": got, "key": key, "dedup": dedup})
            except Exception:  # noqa: BLE001
                pass
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
