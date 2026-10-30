#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Клиент прямой presigned-multipart загрузки в S3 с ВОЗОБНОВЛЕНИЕМ (P0-2/P0-3).

Считает sha256 локального файла, инициирует серверный multipart (партиция
tenant/<субъект>/), заливает части параллельно прямо в Garage по presigned-URL,
затем регистрирует объект через POST /scans/complete. Поддерживает
возобновление: перед загрузкой запрашивает уже загруженные части
(GET /uploads/<id>/parts) и догружает только недостающие.

Использование:
  python3 direct_upload.py --base URL --key KEY --file model.bin [--fmt safetensors] \
      [--workers 8] [--upload-id UID] [--stop-after N]
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request

op = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _req(method, url, key, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Authorization": f"Bearer {key}",
                                          "Content-Type": "application/json"})
    try:
        with op.open(req, timeout=120) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def _put_part(url, data):
    req = urllib.request.Request(url, data=data, method="PUT")
    with op.open(req, timeout=300) as r:
        return r.status, (r.headers.get("ETag") or "").strip('"')


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            c = fh.read(1 << 20)
            if not c:
                break
            h.update(c)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--file", required=True)
    ap.add_argument("--name", default="")
    ap.add_argument("--fmt", default="safetensors")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--upload-id", default="")
    ap.add_argument("--stop-after", type=int, default=0, help="прервать после N частей (тест resume)")
    ap.add_argument("--internal", action="store_true",
                    help="presigned-URL на внутренний адрес S3 (запуск из кластера)")
    args = ap.parse_args()

    path = args.file
    name = args.name or os.path.basename(path)
    size = os.path.getsize(path)
    sha = _sha256(path)
    print(f"[direct] file={name} size={size} sha256={sha[:16]}…")

    t0 = time.monotonic()
    if args.upload_id:
        uid = args.upload_id
        print(f"[direct] возобновление upload_id={uid}")
    else:
        st, init = _req("POST", f"{args.base}/uploads/initiate", args.key,
                        {"name": name, "fmt": args.fmt, "sha256": sha, "size": size,
                         **({"internal": True} if args.internal else {})})
        if st != 200:
            print("[direct] initiate failed:", st, init)
            sys.exit(1)
        uid = init["upload_id"]
        print(f"[direct] key={init['key']} parts={init.get('count')} part_size={init.get('part_size')}")
        if init.get("dedup"):
            print("[direct] dedup=true — объект уже в S3")
            st, rec = _req("POST", f"{args.base}/scans/complete", args.key,
                           {"upload_id": uid, "parts": []})
            print(f"[direct] registered scan_id={rec.get('scan_id')} tenant={rec.get('tenant')}")
            print("[direct] OK" if st == 202 else f"[direct] FAIL complete {st} {rec}")
            return sys.exit(0 if st == 202 else 1)

    st, st_info = _req("GET", f"{args.base}/uploads/{uid}/parts"
             + ("?internal=1" if args.internal else ""), args.key)
    if st != 200:
        print("[direct] parts failed:", st, st_info)
        sys.exit(1)
    part_size = st_info["part_size"]
    count = st_info["count"]
    urls = {int(k): v for k, v in st_info["urls"].items()}
    done = {p["part_number"]: p["etag"] for p in st_info["parts"]}
    print(f"[direct] уже загружено частей: {len(done)}/{count}")

    def part_span(n):
        start = (n - 1) * part_size
        return start, min(part_size, size - start)

    def do_part(n):
        start, ln = part_span(n)
        with open(path, "rb") as fh:
            fh.seek(start)
            stp, et = _put_part(urls[n], fh.read(ln))
        assert stp in (200, 201), f"part {n} status {stp}"
        return n, et

    todo = [n for n in range(1, count + 1) if n not in done]
    if args.stop_after:
        todo = todo[:args.stop_after]
    if todo:
        t_up = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
            for n, et in ex.map(do_part, todo):
                done[n] = et
        print(f"[direct] загружено {len(todo)} частей за {time.monotonic() - t_up:.1f}s")
    if args.stop_after:
        print(f"[direct] ОСТАНОВЛЕНО после {args.stop_after} частей (resume-point)")
        print(f"[direct] RESUME_UPLOAD_ID={uid}")
        sys.exit(42)
    if len(done) < count:
        print(f"[direct] не все части загружены: {len(done)}/{count}")
        sys.exit(1)

    st, rec = _req("POST", f"{args.base}/scans/complete", args.key,
                   {"upload_id": uid, "parts": [{"part_number": n, "etag": done[n]}
                                                for n in sorted(done)]})
    if st != 202:
        print("[direct] complete failed:", st, rec)
        sys.exit(1)
    print(f"[direct] registered scan_id={rec['scan_id']} tenant={rec.get('tenant')} "
          f"total={time.monotonic() - t0:.1f}s")

    deadline = time.time() + 300
    full = {}
    while time.time() < deadline:
        _, full = _req("GET", f"{args.base}/scans/{rec['scan_id']}", args.key)
        if full.get("state") in ("done", "error"):
            break
        time.sleep(3)
    ok = full.get("sha256") == sha and full.get("size") == size and full.get("s3_key")
    print(f"[direct] verdict={full.get('verdict')} state={full.get('state')} s3_key={full.get('s3_key')}")
    print("[direct] OK" if ok else "[direct] FAIL: несоответствие записи")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
