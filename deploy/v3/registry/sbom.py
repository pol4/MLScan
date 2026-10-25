#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Подпись и SBOM образов движков (v3, L1a).

Модель записи реестра образа: digest, источник, размер, подпись (HMAC в тестах; в проде — cosign),
SBOM-идентификатор, статус. Проверка подписи — fail-closed при включённой политике.
"""
from __future__ import annotations

import hashlib
import hmac

from images import is_valid_digest  # type: ignore


def sign_ref(digest: str, key: str) -> str:
    return hmac.new(key.encode(), digest.encode(), hashlib.sha256).hexdigest()


def verify_ref(digest: str, signature: str, key: str) -> bool:
    return hmac.compare_digest(sign_ref(digest, key), signature or "")


def make_image_record(*, digest: str, ref: str = "", source: str = "import", size: int = 0,
                      signature: str = "", sbom: str = "", status: str = "registered") -> dict:
    return {"digest": digest, "ref": ref, "source": source, "size": int(size or 0),
            "signature": signature, "sbom": sbom, "status": status}


def validate_record(rec: dict, key: str = "", require_signature: bool = False) -> tuple[bool, str]:
    if not isinstance(rec, dict):
        return False, "record must be an object"
    if not is_valid_digest(rec.get("digest", "")):
        return False, "invalid digest"
    if require_signature:
        if not key:
            return False, "signature verification requires key"
        if not verify_ref(rec["digest"], rec.get("signature", ""), key):
            return False, "signature invalid"
    return True, "ok"
