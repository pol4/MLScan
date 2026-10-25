#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Бенчмарк ingest Garage (этап P1-5): пропускная способность одиночного PUT
против параллельной multipart-загрузки. Запускается ВНУТРИ кластера (v pod
сервиса тестирования), объект грузится напрямую в Garage.

Использование:
  python3 garage_ingest_bench.py --size-mb 512 [--workers 8] [--json out.json]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, "/opt/s3")
from s3client import S3  # noqa: E402


def _make_file(path, size):
    with open(path, "wb") as fh:
        left = size
        block = os.urandom(1 << 20)
        while left > 0:
            n = min(len(block), left)
            fh.write(block[:n])
            left -= n
    return path


def _sha(path):
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
    ap.add_argument("--size-mb", type=int, default=512)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--json", default="")
    args = ap.parse_args()

    s3 = S3(os.environ["S3_ENDPOINT"], os.environ["S3_ACCESS_KEY"], os.environ["S3_SECRET_KEY"],
            region=os.environ.get("S3_REGION", "garage"), bucket=os.environ["S3_BUCKET"], timeout=900)
    size = args.size_mb * 1024 * 1024
    tmp = os.path.join("/var/tmp", "bench-" + os.urandom(4).hex() + ".bin")
    _make_file(tmp, size)
    sha = _sha(tmp)
    res = {"size": size, "single_mbps": None, "multipart_mbps": None, "workers": args.workers}

    k1 = f"bench/single-{sha[:12]}.bin"
    t = time.monotonic()
    with open(tmp, "rb") as fh:
        s3.put_stream(k1, fh, size, sha)
    res["single_s"] = round(time.monotonic() - t, 2)
    res["single_mbps"] = round(size / res["single_s"] / 1e6, 1)
    s3.delete(k1)

    k2 = f"bench/multi-{sha[:12]}.bin"
    t = time.monotonic()
    with open(tmp, "rb") as fh:
        r = s3.put_stream_multipart(k2, fh, size, sha, part_size=32 * 1024 * 1024,
                                    workers=args.workers)
    res["multi_s"] = round(time.monotonic() - t, 2)
    res["multipart_mbps"] = round(size / res["multi_s"] / 1e6, 1)
    res["multipart_parts"] = r["parts"]
    st, _, resp = s3.get_stream(k2)
    hh = hashlib.sha256()
    if st == 200:
        while True:
            chunk = resp.read(1 << 20)
            if not chunk:
                break
            hh.update(chunk)
    res["verify_ok"] = (st == 200 and hh.hexdigest() == sha)
    s3.delete(k2)
    try:
        os.unlink(tmp)
    except OSError:
        pass

    print(json.dumps(res, ensure_ascii=False, indent=2))
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(res, fh, ensure_ascii=False, indent=2)
    if not res["verify_ok"]:
        sys.exit(1)
    print(f"[bench] single={res['single_mbps']} MB/s, multipart({args.workers})="
          f"{res['multipart_mbps']} MB/s, ×{res['multipart_mbps'] / max(res['single_mbps'], 0.1):.1f}")


if __name__ == "__main__":
    main()
