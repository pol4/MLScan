#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""С АРМ: прямая presigned-multipart загрузка в S3 по **TLS** (P0, TLS-egress S3).

API вызывается через Istio (HTTP, nodePort, Host: api.mlscan.local), а части заливаются
напрямую в S3 через **HTTPS** (Istio TLS-listener 443 -> nodePort 30921, host s3.mlscan.local).
Соединение идёт на IP узла, но заголовок Host = s3.mlscan.local:30921 (как в presigned-URL),
поэтому SigV4 проверяется. Сертификат самоподписанный — проверка выключена (тест).
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import http.client
import json
import os
import socket
import ssl
import sys
import time
import urllib.parse
import urllib.request

op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
CTX = ssl._create_unverified_context()


class ArmApi:
    def __init__(self, node_ip, nodeport, host, key):
        self.ip, self.port, self.host, self.key = node_ip, nodeport, host, key

    def call(self, method, path, payload=None):
        body = json.dumps(payload).encode() if payload is not None else None
        c = http.client.HTTPConnection(self.ip, self.port, timeout=120)
        c.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        c.putheader("Host", self.host)
        c.putheader("Authorization", "Bearer " + self.key)
        if body is not None:
            c.putheader("Content-Type", "application/json")
            c.putheader("Content-Length", str(len(body)))
        c.endheaders()
        if body is not None:
            c.send(body)
        r = c.getresponse(); data = r.read(); c.close()
        try:
            return r.status, json.loads(data or b"{}")
        except Exception:
            return r.status, {"_raw": data[:200].decode("utf-8", "replace")}


def _sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            c = fh.read(1 << 20)
            if not c:
                break
            h.update(c)
    return h.hexdigest()


def _put_tls(url, data, host, port):
    # соединяемся по имени host (правильный SNI/Host), DNS подменяем на IP узла
    u = urllib.parse.urlsplit(url)
    target = u.path + (("?" + u.query) if u.query else "")
    c = http.client.HTTPSConnection(host, port, timeout=300, context=CTX)
    c.putrequest("PUT", target, skip_accept_encoding=True)
    c.putheader("Content-Length", str(len(data)))
    c.endheaders(); c.send(data)
    r = c.getresponse(); etag = (r.getheader("ETag") or "").strip('"'); st = r.status
    r.read(); c.close()
    return st, etag


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--node-ip", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--file", required=True)
    ap.add_argument("--name", default="")
    ap.add_argument("--api-host", default="api.mlscan.local")
    ap.add_argument("--api-nodeport", type=int, default=30217)
    ap.add_argument("--s3-ip", default="")
    ap.add_argument("--s3-port", type=int, default=30921)
    ap.add_argument("--s3-host", default="s3.mlscan.local")
    ap.add_argument("--workers", type=int, default=6)
    args = ap.parse_args()

    s3_ip = args.s3_ip or args.node_ip
    api = ArmApi(args.node_ip, args.api_nodeport, args.api_host, args.key)
    path = args.file
    name = args.name or os.path.basename(path)
    size = os.path.getsize(path)
    sha = _sha(path)
    print(f"[arm-tls] file={name} size={size} sha256={sha[:16]}…")

    st, init = api.call("POST", "/uploads/initiate",
                        {"name": name, "fmt": "safetensors", "sha256": sha, "size": size})
    if st != 200:
        print("[arm-tls] initiate failed:", st, init); sys.exit(1)
    urls = {p["part_number"]: p["url"] for p in init["parts"]}
    sizes = {p["part_number"]: p["size"] for p in init["parts"]}
    sample = next(iter(urls.values()))
    print(f"[arm-tls] presigned scheme/host: {sample.split('/')[0]}//{sample.split('/')[2]}")
    if not sample.startswith("https://"):
        print("[arm-tls] FAIL: presigned-URL не https"); sys.exit(1)
    if ".svc." in sample:
        print("[arm-tls] FAIL: presigned-URL внутренний"); sys.exit(1)

    # SNI/Host = s3.mlscan.local, но TCP идёт на IP узла (подмена DNS в тесте)
    _orig = socket.getaddrinfo
    def _patched(host, port, *a, **k):
        return _orig(s3_ip, port, *a, **k) if host == args.s3_host else _orig(host, port, *a, **k)
    socket.getaddrinfo = _patched
    etags = []
    with open(path, "rb") as fh:
        def do_part(n):
            fh.seek(sum(sizes[i] for i in range(1, n)))
            stp, et = _put_tls(urls[n], fh.read(sizes[n]), args.s3_host, args.s3_port)
            assert stp in (200, 201), f"part {n} status {stp}"
            return n, et
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
            etags = list(ex.map(do_part, range(1, len(urls) + 1)))
    print(f"[arm-tls] parts uploaded via TLS: {len(etags)}")

    st, rec = api.call("POST", "/scans/complete",
                       {"upload_id": init["upload_id"],
                        "parts": [{"part_number": n, "etag": e} for n, e in etags]})
    if st != 202:
        print("[arm-tls] complete failed:", st, rec); sys.exit(1)
    deadline = time.time() + 240
    full = {}
    while time.time() < deadline:
        _, full = api.call("GET", f"/scans/{rec['scan_id']}")
        if full.get("state") in ("done", "error"):
            break
        time.sleep(3)
    ok = full.get("sha256") == sha and full.get("size") == size and full.get("s3_key")
    print(f"[arm-tls] verdict={full.get('verdict')} state={full.get('state')}")
    print("[arm-tls] OK: presigned-multipart по TLS с АРМ работает" if ok else "[arm-tls] FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
