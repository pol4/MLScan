#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Клиент для e2e прототипа многоузлового S3 (P0). Запускается в поде (есть /opt/s3).

Режимы:
  write  — записать 8 МиБ объект (multipart) в кластер, сохранить ожидаемый sha в /tmp, проверить GET;
  read   — прочитать объект по ключу и сверить sha с ожидаемым (/tmp).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile

sys.path.insert(0, "/opt/s3")
from s3client import S3  # noqa: E402

EXPECT = "/tmp/rf_expect.json"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["write", "read"], required=True)
    ap.add_argument("--kid", required=True)
    ap.add_argument("--secret", required=True)
    ap.add_argument("--object-key", default="")
    ap.add_argument("--endpoint", default="http://garage-v3-0.mlscan-v3-data.svc.cluster.local:3900")
    ap.add_argument("--bucket", default="v3prot-test")
    args = ap.parse_args()

    s3 = S3(args.endpoint, args.kid, args.secret, region="garage", bucket=args.bucket, timeout=120)

    if args.mode == "write":
        data = os.urandom(8 * 1024 * 1024)
        sha = hashlib.sha256(data).hexdigest()
        p = tempfile.NamedTemporaryFile(delete=False); p.write(data); p.close()
        key = f"rf/{sha[:12]}.bin"
        with open(p.name, "rb") as fh:
            s3.put_stream_multipart(key, fh, len(data), sha, part_size=2 * 1024 * 1024, workers=4)
        with open(EXPECT, "w") as fh:
            json.dump({"key": key, "sha": sha}, fh)
        st, _, got = s3.get(key)
        ok = st == 200 and hashlib.sha256(got).hexdigest() == sha
        rng = s3.range_get(key, 4 * 1024 * 1024, 1024) == data[4 * 1024 * 1024:4 * 1024 * 1024 + 1024]
        print(f"  [3-node] put/get ok={ok} range_ok={rng}")
        print(key)
        sys.exit(0 if (ok and rng) else 1)

    # read
    exp = json.load(open(EXPECT))
    key = args.object_key or exp["key"]
    st, _, got = s3.get(key)
    ok = st == 200 and hashlib.sha256(got).hexdigest() == exp["sha"]
    rng = s3.range_get(key, 0, 1024) == got[:1024]
    print(f"    get status={st} sha_ok={ok} range_ok={rng}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
