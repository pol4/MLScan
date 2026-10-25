#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Per-tenant envelope-шифрование (v3, P6).

Ключ тенанта выводится из мастер-ключа (HKDF-подобно через HMAC). Шифрование — XOR с
HMAC-кипотоком (counter mode) + HMAC-тег целостности. Это **стенд-ин** (stdlib): демонстрирует
модель per-tenant KMS и fail-closed проверку тега; в проде — AES-GCM/KMS.
"""
from __future__ import annotations

import hashlib
import hmac
import os


def tenant_key(master: bytes, tenant: str) -> bytes:
    return hmac.new(master, ("tenant:" + tenant).encode(), hashlib.sha256).digest()


def _keystream(key: bytes, nonce: bytes, n: int) -> bytes:
    out = bytearray()
    ctr = 0
    while len(out) < n:
        out += hmac.new(key, nonce + ctr.to_bytes(4, "big"), hashlib.sha256).digest()
        ctr += 1
    return bytes(out[:n])


def encrypt(master: bytes, tenant: str, plaintext: bytes, nonce: bytes | None = None) -> dict:
    nonce = nonce or os.urandom(12)
    key = tenant_key(master, tenant)
    ks = _keystream(key, nonce, len(plaintext))
    ct = bytes(a ^ b for a, b in zip(plaintext, ks))
    tag = hmac.new(key, nonce + ct, hashlib.sha256).hexdigest()
    return {"nonce": nonce.hex(), "ct": ct.hex(), "tag": tag, "tenant": tenant}


def decrypt(master: bytes, blob: dict) -> bytes:
    tenant = blob.get("tenant", "")
    key = tenant_key(master, tenant)
    nonce = bytes.fromhex(blob.get("nonce", ""))
    ct = bytes.fromhex(blob.get("ct", ""))
    want = hmac.new(key, nonce + ct, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(want, blob.get("tag", "")):
        raise ValueError("integrity check failed (fail-closed)")
    ks = _keystream(key, nonce, len(ct))
    return bytes(a ^ b for a, b in zip(ct, ks))


def verify(blob: dict, master: bytes) -> bool:
    try:
        decrypt(master, blob)
        return True
    except Exception:  # noqa: BLE001
        return False
