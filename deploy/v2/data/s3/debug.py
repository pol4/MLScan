#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Debug SigV4 к Garage: перебор вариантов подписи, печать канонического запроса."""
import datetime
import hashlib
import hmac
import http.client
import os
import urllib.parse


def _sign(k, m):
    return hmac.new(k, m.encode(), hashlib.sha256).digest()


def signing_key(secret, ds, region, service="s3"):
    k = _sign(("AWS4" + secret).encode(), ds)
    k = _sign(k, region)
    k = _sign(k, service)
    return _sign(k, "aws4_request")


def attempt(name, host, port, bucket, key, access, secret, region, *,
            sign_len=False, host_with_port=True, unsigned=False, print_cr=False):
    body = b"debug-payload"
    path = "/" + bucket + "/" + urllib.parse.quote(key)
    now = datetime.datetime.now(datetime.timezone.utc)
    amz = now.strftime("%Y%m%dT%H%M%SZ")
    ds = now.strftime("%Y%m%d")
    ph = "UNSIGNED-PAYLOAD" if unsigned else hashlib.sha256(body).hexdigest()
    h = {
        "host": f"{host}:{port}" if host_with_port else host,
        "x-amz-content-sha256": ph,
        "x-amz-date": amz,
    }
    if sign_len:
        h["content-length"] = str(len(body))
    sh = sorted(h)
    ch = "".join(f"{k}:{h[k]}\n" for k in sh)
    cr = "\n".join(["PUT", path, "", ch, ";".join(sh), ph])
    scope = f"{ds}/{region}/s3/aws4_request"
    sts = "\n".join(["AWS4-HMAC-SHA256", amz, scope, hashlib.sha256(cr.encode()).hexdigest()])
    sig = hmac.new(signing_key(secret, ds, region), sts.encode(), hashlib.sha256).hexdigest()
    h["Authorization"] = (f"AWS4-HMAC-SHA256 Credential={access}/{scope}, "
                          f"SignedHeaders={';'.join(sh)}, Signature={sig}")
    try:
        c = http.client.HTTPConnection(host, port, timeout=15)
        c.request("PUT", path, body=body, headers=h)
        r = c.getresponse()
        _ = r.read()
        c.close()
        print(f"[{name}] status={r.status}")
        if print_cr:
            print("--- canonical request ---\n" + cr + "\n--- end ---")
        return r.status
    except Exception as e:  # noqa: BLE001
        print(f"[{name}] ERR {type(e).__name__}: {e}")
        return None


host = os.environ["S3_ENDPOINT"].split("//")[1].split(":")[0]
port = int(os.environ["S3_ENDPOINT"].split(":")[-1])
bucket = os.environ["S3_BUCKET"]
access = os.environ["S3_ACCESS_KEY"]
secret = os.environ["S3_SECRET_KEY"]

attempt("v1_baseline", host, port, bucket, "debug/a.txt", access, secret, "garage", print_cr=True)
attempt("v2_sign_len", host, port, bucket, "debug/a.txt", access, secret, "garage", sign_len=True)
attempt("v3_region_useast1", host, port, bucket, "debug/a.txt", access, secret, "us-east-1")
attempt("v4_host_no_port", host, port, bucket, "debug/a.txt", access, secret, "garage", host_with_port=False)
attempt("v5_unsigned_payload", host, port, bucket, "debug/a.txt", access, secret, "garage", unsigned=True)
