#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Проверка Ingest Gateway: загрузка большого файла в S3 + дедуп на повторной загрузке."""
import http.client
import os
import time

HOST = os.environ.get("INGEST_HOST", "mlscan-ingest.mlscan-data.svc.cluster.local")
PORT = int(os.environ.get("INGEST_PORT", "8080"))
SIZE_MB = int(os.environ.get("SIZE_MB", "1024"))
PATH = "/data/big.bin"

os.makedirs("/data", exist_ok=True)
left = SIZE_MB * 1048576
with open(PATH, "wb") as fh:
    while left > 0:
        n = min(4 * 1048576, left)
        fh.write(os.urandom(n))
        left -= n
size = os.path.getsize(PATH)
print(f"file: {size} bytes ({SIZE_MB} MiB)")


def upload(tag: str):
    c = http.client.HTTPConnection(HOST, PORT, timeout=3600)
    c.putrequest("POST", "/uploads?name=big.bin&fmt=raw")
    c.putheader("Content-Length", str(size))
    c.endheaders()
    with open(PATH, "rb") as fh:
        while True:
            chunk = fh.read(1 << 20)
            if not chunk:
                break
            c.send(chunk)
    r = c.getresponse()
    body = r.read()
    c.close()
    print(tag, r.status, body.decode()[:400])
    return r.status, body


t = time.monotonic()
s1, b1 = upload("upload#1")
print("time#1", round(time.monotonic() - t, 2), "s")
t = time.monotonic()
s2, b2 = upload("upload#2(dedup)")
print("time#2", round(time.monotonic() - t, 2), "s")

ok = s1 == 202 and s2 == 202 and b'"dedup": true' in b2.replace(b'"dedup":true', b'"dedup": true')
print("INGEST VERIFY", "OK" if ok else "CHECK")
