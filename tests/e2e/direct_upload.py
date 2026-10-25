#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Клиент прямой presigned-multipart загрузки в S3 (этап P0-2, docs/15 §11.6).

Демонстрирует сценарий «внешний клиент / CI»: считает sha256 локального файла,
инициирует серверный multipart (партиция tenant/<субъект>/), заливает части
параллельно прямо в Garage по presigned-URL, затем регистрирует объект через
POST /scans/complete. Сервис тестирования в передаче данных не участвует.

Использование:
  python3 direct_upload.py --base http://127.0.0.1:8080 --key KEY --file model.bin \
      [--name model.bin] [--fmt safetensors] [--workers 8]
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import sys
import time
import urllib.request
import uuid

op = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _post_json(base, key, path, payload):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(base + path, data=data, method="POST",
                                 headers={"Authorization": f"Bearer {key}",
                                          "Content-Type": "application/json"})
    with op.open(req, timeout=120) as r:
        return r.status, json.loads(r.read())


def _put_part(url, data):
    req = urllib.request.Request(url, data=data, method="PUT")
    with op.open(req, timeout=300) as r:
        return r.status, (r.headers.get("ETag") or "").strip('"')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True, help="URL API сервиса тестирования")
    ap.add_argument("--key", required=True)
    ap.add_argument("--file", required=True)
    ap.add_argument("--name", default="")
    ap.add_argument("--fmt", default="safetensors")
    ap.add_argument("--workers", type=int, default=8)
    args = ap.parse_args()

    path = args.file
    name = args.name or os.path.basename(path)
    size = os.path.getsize(path)
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1 << 20)
            if not chunk:
                break
            h.update(chunk)
    sha = h.hexdigest()
    print(f"[direct] file={name} size={size} sha256={sha[:16]}…")

    t0 = time.monotonic()
    st, init = _post_json(args.base, args.key, "/uploads/initiate",
                          {"name": name, "fmt": args.fmt, "sha256": sha, "size": size})
    if st != 200:
        print("[direct] initiate failed:", st, init)
        sys.exit(1)
    print(f"[direct] key={init['key']} parts={init.get('count')} part_size={init.get('part_size')}")

    etags = []
    if init.get("dedup"):
        print("[direct] dedup=true — объект уже в S3, загрузка пропущена")
    else:
        urls = {p["part_number"]: p["url"] for p in init["parts"]}
        sizes = {p["part_number"]: p["size"] for p in init["parts"]}
        t_up = time.monotonic()
        with open(path, "rb") as fh:
            def do_part(n):
                fh.seek(sum(sizes[i] for i in range(1, n)))
                stp, et = _put_part(urls[n], fh.read(sizes[n]))
                assert stp in (200, 201), f"part {n} status {stp}"
                return n, et
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
                for n, et in ex.map(do_part, range(1, len(urls) + 1)):
                    etags.append((n, et))
        dt = time.monotonic() - t_up
        print(f"[direct] parts uploaded in {dt:.1f}s ({size / dt / 1e6:.0f} MB/s), "
              f"{len(etags)} parts")

    st, rec = _post_json(args.base, args.key, "/scans/complete",
                         {"upload_id": init["upload_id"],
                          "parts": [{"part_number": n, "etag": et} for n, et in etags]})
    if st != 202:
        print("[direct] complete failed:", st, rec)
        sys.exit(1)
    print(f"[direct] registered scan_id={rec['scan_id']} tenant={rec.get('tenant')} "
          f"total={time.monotonic() - t0:.1f}s")

    deadline = time.time() + 300
    full = {}
    while time.time() < deadline:
        req = urllib.request.Request(f"{args.base}/scans/{rec['scan_id']}",
                                     headers={"Authorization": f"Bearer {args.key}"})
        full = json.loads(op.open(req, timeout=60).read())
        if full.get("state") in ("done", "error"):
            break
        time.sleep(3)
    ok = full.get("sha256") == sha and full.get("size") == size and full.get("s3_key")
    print(f"[direct] verdict={full.get('verdict')} state={full.get('state')} "
          f"s3_key={full.get('s3_key')}")
    print("[direct] OK" if ok else "[direct] FAIL: несоответствие записи")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
