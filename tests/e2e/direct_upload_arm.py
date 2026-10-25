#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Клиент прямой presigned-multipart загрузки С АРМ (вне кластера), P0-2/P0-3 + P3 (S3 наружу).

API-вызовы идут через Istio-гейтвей по nodePort (Host: api.mlscan.local), а части
заливаются напрямую в S3 (Garage) по адресу, указанному в presigned-URL — который на
стенде ведёт на Istio TCP-passthrough (nodePort 31317 -> Garage:3900).

Использование:
  python3 direct_upload_arm.py --node-ip 192.168.20.116 --key KEY --file model.bin \
      [--api-host api.mlscan.local] [--api-nodeport 30217] [--fmt safetensors] [--workers 8]
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import http.client
import json
import os
import sys
import time
import urllib.request

op = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class ArmApi:
    """API через Istio по nodePort с заголовком Host (без DNS-правок на АРМ)."""

    def __init__(self, node_ip, nodeport, host, key):
        self.node_ip, self.nodeport, self.host, self.key = node_ip, nodeport, host, key

    def call(self, method, path, payload=None):
        body = json.dumps(payload).encode() if payload is not None else None
        conn = http.client.HTTPConnection(self.node_ip, self.nodeport, timeout=120)
        conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        conn.putheader("Host", self.host)
        conn.putheader("Authorization", "Bearer " + self.key)
        if body is not None:
            conn.putheader("Content-Type", "application/json")
            conn.putheader("Content-Length", str(len(body)))
        conn.endheaders()
        if body is not None:
            conn.send(body)
        r = conn.getresponse()
        data = r.read()
        conn.close()
        try:
            return r.status, json.loads(data or b"{}")
        except Exception:
            return r.status, {"_raw": data[:200].decode("utf-8", "replace")}


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            c = fh.read(1 << 20)
            if not c:
                break
            h.update(c)
    return h.hexdigest()


def _put_part(url, data):
    r = urllib.request.Request(url, data=data, method="PUT")
    with op.open(r, timeout=300) as resp:
        return resp.status, (resp.headers.get("ETag") or "").strip('"')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--node-ip", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--file", required=True)
    ap.add_argument("--name", default="")
    ap.add_argument("--api-host", default="api.mlscan.local")
    ap.add_argument("--api-nodeport", type=int, default=30217)
    ap.add_argument("--fmt", default="safetensors")
    ap.add_argument("--workers", type=int, default=8)
    args = ap.parse_args()

    api = ArmApi(args.node_ip, args.api_nodeport, args.api_host, args.key)
    path = args.file
    name = args.name or os.path.basename(path)
    size = os.path.getsize(path)
    sha = _sha256(path)
    print(f"[arm] file={name} size={size} sha256={sha[:16]}…")

    t0 = time.monotonic()
    st, init = api.call("POST", "/uploads/initiate",
                        {"name": name, "fmt": args.fmt, "sha256": sha, "size": size})
    if st != 200:
        print("[arm] initiate failed:", st, init); sys.exit(1)
    print(f"[arm] key={init['key']}")
    if init.get("dedup"):
        st, rec = api.call("POST", "/scans/complete", {"upload_id": init["upload_id"], "parts": []})
        print("[arm] dedup, registered", st, rec.get("scan_id"))
        return sys.exit(0 if st == 202 else 1)

    urls = {p["part_number"]: p["url"] for p in init["parts"]}
    sizes = {p["part_number"]: p["size"] for p in init["parts"]}
    # Проверяем, что presigned-URL ведут на внешний (не внутрикластерный) адрес
    sample = next(iter(urls.values()))
    print(f"[arm] presigned host: {sample.split('/')[2]}")
    if ".svc." in sample:
        print("[arm] FAIL: presigned-URL указывает на внутрикластерный адрес"); sys.exit(1)

    etags = []
    t_up = time.monotonic()
    with open(path, "rb") as fh:
        def do_part(n):
            fh.seek(sum(sizes[i] for i in range(1, n)))
            stp, et = _put_part(urls[n], fh.read(sizes[n]))
            assert stp in (200, 201), f"part {n} status {stp}"
            return n, et
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
            etags = list(ex.map(do_part, range(1, len(urls) + 1)))
    dt = time.monotonic() - t_up
    print(f"[arm] parts uploaded: {len(etags)} за {dt:.1f}s ({size / dt / 1e6:.0f} MB/s)")

    st, rec = api.call("POST", "/scans/complete",
                       {"upload_id": init["upload_id"],
                        "parts": [{"part_number": n, "etag": e} for n, e in etags]})
    if st != 202:
        print("[arm] complete failed:", st, rec); sys.exit(1)
    print(f"[arm] registered scan_id={rec['scan_id']} tenant={rec.get('tenant')} "
          f"total={time.monotonic() - t0:.1f}s")

    deadline = time.time() + 300
    full = {}
    while time.time() < deadline:
        _, full = api.call("GET", f"/scans/{rec['scan_id']}")
        if full.get("state") in ("done", "error"):
            break
        time.sleep(3)
    ok = full.get("sha256") == sha and full.get("size") == size and full.get("s3_key")
    print(f"[arm] verdict={full.get('verdict')} state={full.get('state')}")
    print("[arm] OK: прямая загрузка с АРМ через Istio (S3 TCP-passthrough) работает"
          if ok else "[arm] FAIL: несоответствие записи")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
