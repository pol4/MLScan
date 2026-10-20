#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Минимальный S3-клиент (SigV4, path-style) на stdlib — для интеграции MLScan с S3.

Поддерживает: PUT/GET/HEAD/DELETE/build (presigned не реализован).
Предназначен для внутреннего S3-совместимого хранилища (Garage/MinIO).
"""
from __future__ import annotations

import datetime
import hashlib
import hmac
import http.client
import urllib.parse


def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def _signing_key(secret: str, datestamp: str, region: str, service: str) -> bytes:
    k = _sign(("AWS4" + secret).encode(), datestamp)
    k = _sign(k, region)
    k = _sign(k, service)
    return _sign(k, "aws4_request")


class S3:
    def __init__(self, endpoint: str, access: str, secret: str,
                 region: str = "garage", bucket: str = "", timeout: int = 300):
        u = urllib.parse.urlparse(endpoint)
        self.host = u.hostname
        self.port = u.port or 3900
        self.secure = (u.scheme == "https")
        self.access, self.secret, self.region = access, secret, region
        self.bucket = bucket
        self.timeout = timeout

    def _conn(self):
        if self.secure:
            return http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout)
        return http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)

    def _request(self, method: str, key: str, body: bytes = b"", bucket: str | None = None,
                 extra: dict | None = None):
        bkt = bucket if bucket is not None else self.bucket
        path = "/" + bkt + (("/" + urllib.parse.quote(key)) if key else "")
        now = datetime.datetime.now(datetime.timezone.utc)
        amzdate = now.strftime("%Y%m%dT%H%M%SZ")
        datestamp = now.strftime("%Y%m%d")
        payload_hash = hashlib.sha256(body).hexdigest()
        headers = {
            "host": f"{self.host}:{self.port}",
            "x-amz-content-sha256": payload_hash,
            "x-amz-date": amzdate,
        }
        if extra:
            headers.update({k.lower(): v for k, v in extra.items()})
        signed = sorted(headers)
        canonical_headers = "".join(f"{h}:{headers[h]}\n" for h in signed)
        signed_headers = ";".join(signed)
        canonical_request = "\n".join([method, path, "", canonical_headers, signed_headers, payload_hash])
        scope = f"{datestamp}/{self.region}/s3/aws4_request"
        string_to_sign = "\n".join([
            "AWS4-HMAC-SHA256", amzdate, scope,
            hashlib.sha256(canonical_request.encode()).hexdigest()])
        sig = hmac.new(_signing_key(self.secret, datestamp, self.region, "s3"),
                       string_to_sign.encode(), hashlib.sha256).hexdigest()
        headers["Authorization"] = (f"AWS4-HMAC-SHA256 Credential={self.access}/{scope}, "
                                    f"SignedHeaders={signed_headers}, Signature={sig}")
        conn = self._conn()
        conn.request(method, path, body=body if method in ("PUT", "POST") else None, headers=headers)
        r = conn.getresponse()
        data = r.read()
        conn.close()
        return r.status, dict(r.getheaders()), data

    def put(self, key: str, body: bytes, content_type: str = "application/octet-stream"):
        return self._request("PUT", key, body, extra={"content-type": content_type})

    def get(self, key: str):
        return self._request("GET", key)

    def head(self, key: str):
        return self._request("HEAD", key)

    def delete(self, key: str):
        return self._request("DELETE", key)


    def put_stream(self, key: str, stream, length: int, sha256_hex: str,
                   content_type: str = "application/octet-stream"):
        """Потоковая PUT-загрузка: payload-hash известен заранее, тело читается из stream."""
        path = "/" + self.bucket + (("/" + urllib.parse.quote(key)) if key else "")
        now = datetime.datetime.now(datetime.timezone.utc)
        amzdate = now.strftime("%Y%m%dT%H%M%SZ")
        datestamp = now.strftime("%Y%m%d")
        headers = {
            "host": f"{self.host}:{self.port}",
            "x-amz-content-sha256": sha256_hex,
            "x-amz-date": amzdate,
            "content-type": content_type,
        }
        signed = sorted(headers)
        canonical_headers = "".join(f"{h}:{headers[h]}\n" for h in signed)
        signed_headers = ";".join(signed)
        canonical_request = "\n".join(["PUT", path, "", canonical_headers, signed_headers, sha256_hex])
        scope = f"{datestamp}/{self.region}/s3/aws4_request"
        string_to_sign = "\n".join(["AWS4-HMAC-SHA256", amzdate, scope,
                                     hashlib.sha256(canonical_request.encode()).hexdigest()])
        sig = hmac.new(_signing_key(self.secret, datestamp, self.region, "s3"),
                       string_to_sign.encode(), hashlib.sha256).hexdigest()
        auth = (f"AWS4-HMAC-SHA256 Credential={self.access}/{scope}, "
                f"SignedHeaders={signed_headers}, Signature={sig}")
        conn = self._conn()
        conn.putrequest("PUT", path)
        conn.putheader("x-amz-content-sha256", sha256_hex)
        conn.putheader("x-amz-date", amzdate)
        conn.putheader("Content-Type", content_type)
        conn.putheader("Content-Length", str(length))
        conn.putheader("Authorization", auth)
        conn.endheaders()
        sent = 0
        while sent < length:
            chunk = stream.read(min(1 << 20, length - sent))
            if not chunk:
                break
            conn.send(chunk)
            sent += len(chunk)
        r = conn.getresponse()
        data = r.read()
        conn.close()
        return r.status, dict(r.getheaders()), data


    def get_stream(self, key: str):
        """Потоковый GET: возвращает (status, headers, response) для чтения тела чанками."""
        path = "/" + self.bucket + (("/" + urllib.parse.quote(key)) if key else "")
        now = datetime.datetime.now(datetime.timezone.utc)
        amzdate = now.strftime("%Y%m%dT%H%M%SZ")
        datestamp = now.strftime("%Y%m%d")
        empty = hashlib.sha256(b"").hexdigest()
        headers = {"host": f"{self.host}:{self.port}",
                   "x-amz-content-sha256": empty, "x-amz-date": amzdate}
        signed = sorted(headers)
        canonical_headers = "".join(f"{h}:{headers[h]}\n" for h in signed)
        canonical_request = "\n".join(["GET", path, "", canonical_headers, ";".join(signed), empty])
        scope = f"{datestamp}/{self.region}/s3/aws4_request"
        string_to_sign = "\n".join(["AWS4-HMAC-SHA256", amzdate, scope,
                                     hashlib.sha256(canonical_request.encode()).hexdigest()])
        sig = hmac.new(_signing_key(self.secret, datestamp, self.region, "s3"),
                       string_to_sign.encode(), hashlib.sha256).hexdigest()
        auth = (f"AWS4-HMAC-SHA256 Credential={self.access}/{scope}, "
                f"SignedHeaders={';'.join(signed)}, Signature={sig}")
        conn = self._conn()
        conn.putrequest("GET", path)
        conn.putheader("x-amz-content-sha256", empty)
        conn.putheader("x-amz-date", amzdate)
        conn.putheader("Authorization", auth)
        conn.endheaders()
        r = conn.getresponse()
        return r.status, dict(r.getheaders()), r

    def exists(self, key: str) -> bool:
        try:
            status, _, _ = self.head(key)
            return status == 200
        except Exception:
            return False
