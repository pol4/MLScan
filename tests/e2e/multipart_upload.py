#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""E2E-тест загрузки большого файла через API сервиса тестирования (этап P0-1).

Проверяет, что объект крупнее порога уходит в S3 параллельными частями
(multipart), а не одиночным PUT: в записи скана ожидаются s3_multipart=true и
s3_parts>=2, sha256/size совпадают с исходными.

Использование:
  python3 tests/e2e/multipart_upload.py --base http://127.0.0.1:18080 --key <API_KEY> \
      [--size-mb 130] [--part-size 64] [--fmt safetensors]

Для проверки содержимого объекта в S3 (--verify-s3) нужен доступ kubectl.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import sys
import time
import urllib.parse
import urllib.request
import uuid

op = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _get(base, key, path):
    req = urllib.request.Request(base + path, headers={"Authorization": f"Bearer {key}"})
    return json.loads(op.open(req, timeout=60).read())


def _stream_upload(base, key, path, name, fmt):
    u = urllib.parse.urlparse(base)
    size = os.path.getsize(path)
    q = urllib.parse.urlencode({"name": name, "fmt": fmt})
    conn = http.client.HTTPConnection(u.hostname, u.port, timeout=300)
    conn.putrequest("POST", f"/scans/upload?{q}")
    conn.putheader("Authorization", f"Bearer {key}")
    conn.putheader("Content-Length", str(size))
    conn.endheaders()
    read = 0
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1 << 20)
            if not chunk:
                break
            conn.send(chunk)
            read += len(chunk)
    r = conn.getresponse()
    body = r.read()
    conn.close()
    return r.status, json.loads(body)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--size-mb", type=int, default=130)
    ap.add_argument("--fmt", default="safetensors")
    ap.add_argument("--timeout", type=int, default=300)
    args = ap.parse_args()

    tmp = f"/tmp/mlscan-e2e-{uuid.uuid4().hex}.bin"
    total = args.size_mb * 1024 * 1024
    h = hashlib.sha256()
    with open(tmp, "wb") as fh:
        left = total
        while left > 0:
            chunk = os.urandom(min(1 << 20, left))
            fh.write(chunk)
            h.update(chunk)
            left -= len(chunk)
    sha = h.hexdigest()
    print(f"[e2e] file {tmp} size={total} sha256={sha[:16]}…")

    t0 = time.monotonic()
    st, rec = _stream_upload(args.base, args.key, tmp, os.path.basename(tmp), args.fmt)
    dt = time.monotonic() - t0
    assert st == 202, f"upload status {st}: {rec}"
    sid = rec["scan_id"]
    mbps = total / dt / 1e6
    print(f"[e2e] upload 202 scan_id={sid} in {dt:.1f}s ({mbps:.0f} MB/s)")

    deadline = time.time() + args.timeout
    full = {}
    while time.time() < deadline:
        full = _get(args.base, args.key, f"/scans/{sid}")
        if full.get("state") in ("done", "error"):
            break
        time.sleep(3)

    fails = []
    if full.get("sha256") != sha:
        fails.append(f"sha256 mismatch: {full.get('sha256')} != {sha}")
    if full.get("size") != total:
        fails.append(f"size mismatch: {full.get('size')} != {total}")
    if not full.get("s3_key"):
        fails.append("s3_key отсутствует (S3 не использован)")
    if not full.get("s3_multipart"):
        fails.append("s3_multipart не выставлен (multipart не применён)")
    if (full.get("s3_parts") or 0) < 2:
        fails.append(f"s3_parts={full.get('s3_parts')} (ожидалось >=2)")

    print(f"[e2e] verdict={full.get('verdict')} s3_key={full.get('s3_key')} "
          f"multipart={full.get('s3_multipart')} parts={full.get('s3_parts')}")
    try:
        os.unlink(tmp)
    except OSError:
        pass
    if fails:
        print("[e2e] FAIL:")
        for f in fails:
            print("   -", f)
        sys.exit(1)
    print("[e2e] OK: multipart-загрузка подтверждена")


if __name__ == "__main__":
    main()
