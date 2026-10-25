#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Минимальный S3-клиент (SigV4, path-style) на stdlib — для интеграции MLScan с S3.

Поддерживает: PUT/GET/HEAD/DELETE и Multipart Upload (CreateMultipartUpload /
UploadPart / CompleteMultipartUpload / AbortMultipartUpload) с параллельной
загрузкой частей (этап P0-1, docs/15 §11.6). Presigned-URL не реализован.
Предназначен для внутреннего S3-совместимого хранилища (Garage/MinIO).
"""
from __future__ import annotations

import concurrent.futures
import datetime
import hashlib
import hmac
import http.client
import urllib.parse

EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def _signing_key(secret: str, datestamp: str, region: str, service: str) -> bytes:
    k = _sign(("AWS4" + secret).encode(), datestamp)
    k = _sign(k, region)
    k = _sign(k, service)
    return _sign(k, "aws4_request")


def _enc(s: str) -> str:
    return urllib.parse.quote(s, safe="-_.~")


class S3:
    def __init__(self, endpoint: str, access: str, secret: str,
                 region: str = "garage", bucket: str = "", timeout: int = 300,
                 public_endpoint: str = ""):
        u = urllib.parse.urlparse(endpoint)
        self.host = u.hostname
        self.port = u.port or 3900
        self.secure = (u.scheme == "https")
        self.access, self.secret, self.region = access, secret, region
        self.bucket = bucket
        self.timeout = timeout
        # Публичный адрес S3 для presigned-URL (клиент снаружи кластера).
        pe = public_endpoint or endpoint
        pu = urllib.parse.urlparse(pe)
        self.pub_host = pu.hostname or self.host
        self.pub_port = pu.port or (443 if pu.scheme == "https" else 3900)
        self.pub_secure = (pu.scheme == "https")

    def _conn(self):
        if self.secure:
            return http.client.HTTPSConnection(self.host, self.port, timeout=self.timeout)
        return http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)

    # --- внутреннее: построение пути/подпись ---------------------------------
    def _path(self, key: str, bucket: str | None = None) -> str:
        bkt = bucket if bucket is not None else self.bucket
        return "/" + bkt + (("/" + urllib.parse.quote(key)) if key else "")

    @staticmethod
    def _canonical_query(query) -> str:
        if not query:
            return ""
        pairs = sorted((k, "" if v is None else str(v)) for k, v in query)
        return "&".join(f"{_enc(k)}={_enc(v)}" for k, v in pairs)

    def _send(self, method: str, key: str, query=None, body: bytes | None = None,
              payload_hash: str | None = None, extra: dict | None = None,
              stream=None, length: int | None = None, bucket: str | None = None,
              read: bool = True):
        path = self._path(key, bucket)
        cq = self._canonical_query(query)
        now = datetime.datetime.now(datetime.timezone.utc)
        amzdate = now.strftime("%Y%m%dT%H%M%SZ")
        datestamp = now.strftime("%Y%m%d")
        if payload_hash is None:
            payload_hash = hashlib.sha256(body).hexdigest() if body is not None else EMPTY_SHA256
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
        canonical_request = "\n".join([method, path, cq, canonical_headers, signed_headers, payload_hash])
        scope = f"{datestamp}/{self.region}/s3/aws4_request"
        string_to_sign = "\n".join([
            "AWS4-HMAC-SHA256", amzdate, scope,
            hashlib.sha256(canonical_request.encode()).hexdigest()])
        sig = hmac.new(_signing_key(self.secret, datestamp, self.region, "s3"),
                       string_to_sign.encode(), hashlib.sha256).hexdigest()
        headers["Authorization"] = (f"AWS4-HMAC-SHA256 Credential={self.access}/{scope}, "
                                    f"SignedHeaders={signed_headers}, Signature={sig}")
        req_path = path + (("?" + cq) if cq else "")
        conn = self._conn()
        if stream is not None:
            conn.putrequest(method, req_path)
            for h in ("x-amz-content-sha256", "x-amz-date"):
                conn.putheader(h, headers[h])
            if extra:
                for k, v in extra.items():
                    conn.putheader(k, v)
            conn.putheader("Content-Length", str(length or 0))
            conn.putheader("Authorization", headers["Authorization"])
            conn.endheaders()
            sent = 0
            total = length or 0
            while sent < total:
                chunk = stream.read(min(1 << 20, total - sent))
                if not chunk:
                    break
                conn.send(chunk)
                sent += len(chunk)
        else:
            conn.request(method, req_path,
                         body=body if method in ("PUT", "POST") else None, headers=headers)
        r = conn.getresponse()
        if not read:
            return r.status, dict(r.getheaders()), r
        data = r.read()
        conn.close()
        return r.status, dict(r.getheaders()), data

    # --- базовые операции ----------------------------------------------------
    def put(self, key: str, body: bytes, content_type: str = "application/octet-stream"):
        return self._send("PUT", key, body=body, extra={"content-type": content_type})

    def get(self, key: str):
        return self._send("GET", key)

    def head(self, key: str):
        return self._send("HEAD", key)

    def delete(self, key: str):
        return self._send("DELETE", key)

    def put_stream(self, key: str, stream, length: int, sha256_hex: str,
                   content_type: str = "application/octet-stream"):
        """Потоковая PUT-загрузка: payload-hash известен заранее, тело читается из stream."""
        return self._send("PUT", key, payload_hash=sha256_hex, stream=stream, length=length,
                          extra={"content-type": content_type})

    def get_stream(self, key: str):
        """Потоковый GET: возвращает (status, headers, response) для чтения тела чанками."""
        return self._send("GET", key, read=False)

    def exists(self, key: str) -> bool:
        try:
            status, _, _ = self.head(key)
            return status == 200
        except Exception:
            return False

    # --- Multipart Upload (P0-1) --------------------------------------------
    def create_multipart(self, key: str,
                         content_type: str = "application/octet-stream") -> str:
        st, _, data = self._send("POST", key, query=[("uploads", "")],
                                 extra={"content-type": content_type})
        if st not in (200, 201):
            raise RuntimeError(f"create_multipart status {st}: {data[:200]!r}")
        return _xml_tag(data, "UploadId")

    def upload_part(self, key: str, upload_id: str, part_number: int, body: bytes,
                    content_type: str = "application/octet-stream") -> str:
        st, hd, _ = self._send("PUT", key,
                               query=[("partNumber", str(part_number)), ("uploadId", upload_id)],
                               body=body, extra={"content-type": content_type})
        if st not in (200, 201):
            raise RuntimeError(f"upload_part {part_number} status {st}")
        return (hd.get("ETag") or hd.get("etag") or "").strip('"')

    def upload_part_stream(self, key: str, upload_id: str, part_number: int, stream,
                           length: int, content_type: str = "application/octet-stream") -> str:
        st, hd, _ = self._send("PUT", key,
                               query=[("partNumber", str(part_number)), ("uploadId", upload_id)],
                               stream=stream, length=length, extra={"content-type": content_type})
        if st not in (200, 201):
            raise RuntimeError(f"upload_part {part_number} status {st}")
        return (hd.get("ETag") or hd.get("etag") or "").strip('"')

    def complete_multipart(self, key: str, upload_id: str, parts):
        body = ('<?xml version="1.0" encoding="UTF-8"?><CompleteMultipartUpload>'
                + "".join(f"<Part><PartNumber>{n}</PartNumber><ETag>\"{et}\"</ETag></Part>"
                          for n, et in parts)
                + "</CompleteMultipartUpload>").encode()
        return self._send("POST", key, query=[("uploadId", upload_id)], body=body,
                          extra={"content-type": "application/xml"})

    def abort_multipart(self, key: str, upload_id: str):
        return self._send("DELETE", key, query=[("uploadId", upload_id)])

    # --- Presigned URL (query-подпись, P0-2) --------------------------------
    def presign(self, method: str, key: str, query=None, expires: int = 3600,
                extra_headers: dict | None = None) -> str:
        """Сформировать presigned URL (SigV4 query) для метода/ключа.

        Позволяет клиенту (браузер/aws-cli/rclone) обращаться прямо к S3 без секретов.
        """
        path = self._path(key)
        now = datetime.datetime.now(datetime.timezone.utc)
        amzdate = now.strftime("%Y%m%dT%H%M%SZ")
        datestamp = now.strftime("%Y%m%d")
        scope = f"{datestamp}/{self.region}/s3/aws4_request"
        signed = ["host"] + sorted((extra_headers or {}).keys())
        params = [
            ("X-Amz-Algorithm", "AWS4-HMAC-SHA256"),
            ("X-Amz-Credential", f"{self.access}/{scope}"),
            ("X-Amz-Date", amzdate),
            ("X-Amz-Expires", str(int(expires))),
            ("X-Amz-SignedHeaders", ";".join(signed)),
        ]
        for k, v in (query or []):
            params.append((k, v))
        cq = self._canonical_query(params)
        hdrs = {"host": f"{self.pub_host}:{self.pub_port}"}
        hdrs.update({k.lower(): v for k, v in (extra_headers or {}).items()})
        canonical_headers = "".join(f"{h}:{hdrs[h]}\n" for h in signed)
        canonical_request = "\n".join([method, path, cq, canonical_headers,
                                       ";".join(signed), "UNSIGNED-PAYLOAD"])
        string_to_sign = "\n".join(["AWS4-HMAC-SHA256", amzdate, scope,
                                    hashlib.sha256(canonical_request.encode()).hexdigest()])
        sig = hmac.new(_signing_key(self.secret, datestamp, self.region, "s3"),
                       string_to_sign.encode(), hashlib.sha256).hexdigest()
        scheme = "https" if self.pub_secure else "http"
        return f"{scheme}://{self.pub_host}:{self.pub_port}{path}?{cq}&X-Amz-Signature={sig}"

    def presign_upload_part(self, key: str, upload_id: str, part_number: int,
                            expires: int = 3600) -> str:
        return self.presign("PUT", key,
                            query=[("partNumber", str(part_number)), ("uploadId", upload_id)],
                            expires=expires)

    def presign_create_multipart(self, key: str, expires: int = 3600) -> str:
        return self.presign("POST", key, query=[("uploads", "")], expires=expires)

    def presign_complete_multipart(self, key: str, upload_id: str, expires: int = 3600) -> str:
        return self.presign("POST", key, query=[("uploadId", upload_id)], expires=expires)

    # --- высокоуровневые загрузки -------------------------------------------
    def _multipart_upload(self, key: str, stream, length: int, part_size: int, workers: int,
                          content_type: str, sha256_hex: str | None = None,
                          progress=None) -> dict:
        part_size = max(int(part_size), 1)
        workers = max(int(workers), 1)
        uid = self.create_multipart(key, content_type)
        hasher = hashlib.sha256()
        results: dict[int, str] = {}
        futures: dict[int, concurrent.futures.Future] = {}
        n = 1
        remaining = length
        sent = 0

        def _one(num: int, chunk: bytes) -> str:
            et = self.upload_part(key, uid, num, chunk, content_type)
            md5 = hashlib.md5(chunk).hexdigest()
            if et and et != md5:
                raise RuntimeError(f"part {num} etag mismatch: server={et} md5={md5}")
            return et

        pool = concurrent.futures.ThreadPoolExecutor(max_workers=workers)
        try:
            while remaining > 0:
                chunk = stream.read(min(part_size, remaining))
                if not chunk:
                    break
                hasher.update(chunk)
                futures[n] = pool.submit(_one, n, chunk)
                n += 1
                sent += len(chunk)
                remaining -= len(chunk)
                if progress:
                    progress(sent, length)
                if len(futures) >= workers * 2:
                    done_n = next(iter(futures))
                    results[done_n] = futures.pop(done_n).result()
            for nn, fut in futures.items():
                results[nn] = fut.result()
        except Exception:
            pool.shutdown(wait=False, cancel_futures=True)
            try:
                self.abort_multipart(key, uid)
            except Exception:
                pass
            raise
        else:
            pool.shutdown(wait=True)
        parts = [(nn, results[nn]) for nn in sorted(results)]
        st, hd, data = self.complete_multipart(key, uid, parts)
        if st not in (200, 201):
            raise RuntimeError(f"complete_multipart status {st}: {data[:200]!r}")
        computed = hasher.hexdigest()
        etag = (hd.get("ETag") or hd.get("etag") or "").strip('"') or _xml_tag(data, "ETag")
        return {"status": st, "etag": etag,
                "sha256": sha256_hex or computed, "sha256_computed": computed,
                "size": sent, "parts": len(parts), "multipart": True, "upload_id": uid}

    def put_file_multipart(self, key: str, path: str, part_size: int = 64 * 1024 * 1024,
                           workers: int = 8, content_type: str = "application/octet-stream",
                           progress=None) -> dict:
        """Параллельная multipart-загрузка файла с диска (потоковое чтение частей)."""
        import os
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            return self._multipart_upload(key, fh, size, part_size, workers, content_type,
                                          progress=progress)

    def put_stream_multipart(self, key: str, stream, length: int, sha256_hex: str,
                             part_size: int = 64 * 1024 * 1024, workers: int = 8,
                             content_type: str = "application/octet-stream",
                             progress=None) -> dict:
        """Параллельная multipart-загрузка из потока; sha256 задаётся заранее."""
        return self._multipart_upload(key, stream, length, part_size, workers, content_type,
                                      sha256_hex=sha256_hex, progress=progress)


def _xml_tag(data: bytes, tag: str) -> str:
    import re
    m = re.search(rf"<{tag}>(.*?)</{tag}>", data.decode("utf-8", "replace"), re.S)
    return m.group(1).strip() if m else ""
