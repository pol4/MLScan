#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Smoke-тест S3: PUT/GET/HEAD объекта, проверка содержимого."""
import os
import sys

sys.path.insert(0, "/opt/s3")
from s3client import S3  # noqa: E402

s3 = S3(os.environ["S3_ENDPOINT"], os.environ["S3_ACCESS_KEY"],
        os.environ["S3_SECRET_KEY"], region=os.environ.get("S3_REGION", "garage"),
        bucket=os.environ["S3_BUCKET"])
payload = b"mlscan-smoke-" + os.urandom(6).hex().encode()

st, _, _ = s3.put("smoke/hello.txt", payload, "text/plain")
print("PUT", st)
st2, _, body = s3.get("smoke/hello.txt")
print("GET", st2, "match", body == payload)
st3, _, _ = s3.head("smoke/hello.txt")
print("HEAD", st3)
ok = st in (200, 201) and st2 == 200 and body == payload and st3 == 200
print("S3 SMOKE", "OK" if ok else "FAIL")
sys.exit(0 if ok else 1)
