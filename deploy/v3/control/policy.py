#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Версионирование и подпись политик (v3, P2).

Политика — версионируемый и подписываемый артефакт: канонический JSON → sha256 (версия/идентичность),
HMAC-подпись (подпись/проверка). Скан фиксирует использованную версию политики (воспроизводимость).
"""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field


def canonical(content: dict) -> str:
    return json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def content_hash(content: dict) -> str:
    return hashlib.sha256(canonical(content).encode()).hexdigest()


def sign(content: dict, key: str) -> str:
    return hmac.new(key.encode(), content_hash(content).encode(), hashlib.sha256).hexdigest()


def verify(content: dict, signature: str, key: str) -> bool:
    return hmac.compare_digest(sign(content, key), signature or "")


def validate(content: dict) -> tuple[bool, str]:
    """Базовая валидация схемы политики."""
    if not isinstance(content, dict):
        return False, "policy must be an object"
    if "rules" not in content or not isinstance(content["rules"], list):
        return False, "rules[] обязателен"
    for i, r in enumerate(content["rules"]):
        if not isinstance(r, dict):
            return False, f"rule[{i}] должен быть объектом"
        for k in ("id", "when", "action"):
            if k not in r:
                return False, f"rule[{i}]: нет поля '{k}'"
        if r["action"] not in ("block", "quarantine", "allow"):
            return False, f"rule[{i}]: недопустимый action '{r['action']}'"
    return True, "ok"


@dataclass(frozen=True)
class PolicyVersion:
    version: str
    content: dict
    signature: str = ""
    digest: str = field(default="")

    def __post_init__(self):
        if not self.digest:
            object.__setattr__(self, "digest", content_hash(self.content))


def make_policy(version: str, content: dict, key: str = "") -> PolicyVersion:
    ok, why = validate(content)
    if not ok:
        raise ValueError(why)
    return PolicyVersion(version=version, content=content,
                         signature=sign(content, key) if key else "")
