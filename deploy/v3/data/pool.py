#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Content-addressed общий пул объектов (v3, P0).

Ключ объекта НЕ включает тенанта (в отличие от v2-схемы `tenant/<t>/<sha>/<name>`), что даёт
дедупликацию между тенантами; изоляция — через ссылки/ACL (`objectrefs.py`).
"""
from __future__ import annotations

import re

_SHA = re.compile(r"^[0-9a-f]{64}$")


def is_sha256(value: str) -> bool:
    return bool(isinstance(value, str) and _SHA.match(value))


def pool_key(sha256: str) -> str:
    """Ключ общего пула: objects/<aa>/<bb>/<sha256> (aa/bb — префиксы для шардирования)."""
    if not is_sha256(sha256):
        raise ValueError("sha256 must be 64 lowercase hex chars")
    s = sha256.lower()
    return f"objects/{s[:2]}/{s[2:4]}/{s}"
