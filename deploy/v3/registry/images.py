#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Импорт и валидация образов движков (v3, L1a).

Образ допускается к запуску только: из разрешённого реестра (allowlist), **по digest**
(`@sha256:…`). Тег как идентификатор запуска запрещён. Здесь — разбор/валидация ссылок и ключ
хранения OCI-архива в S3 (`registry/…`).
"""
from __future__ import annotations

import re

DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def parse_ref(ref: str) -> dict:
    """Разобрать ссылку вида [registry/]repo[:tag][@sha256:…] (упрощённо, без строгого Docker-грамматика)."""
    ref = (ref or "").strip()
    digest = ""
    if "@" in ref:
        ref, digest = ref.rsplit("@", 1)
    registry, _, repo = ref.partition("/")
    if "/" not in ref:          # без реестра: registry пуст, repo = ref
        registry, repo = "", ref
    tag = ""
    if ":" in repo and not repo.rsplit(":", 1)[1].startswith("sha256"):
        repo, tag = repo.rsplit(":", 1)
    return {"registry": registry, "repo": repo, "tag": tag, "digest": digest,
            "ref": (f"{registry}/{repo}" if registry else repo)}


def is_valid_digest(digest: str) -> bool:
    return bool(isinstance(digest, str) and DIGEST_RE.match(digest))


def validate_ref(ref: str, allowlist=None) -> tuple[bool, str]:
    """Проверка для допуска к запуску/импорту: digest обязателен; реестр — из allowlist (если задан)."""
    p = parse_ref(ref)
    if not is_valid_digest(p["digest"]):
        return False, "образ должен быть указан по digest (@sha256:<64hex>)"
    if allowlist:
        reg = p["registry"] or ""
        if reg not in allowlist:
            return False, f"реестр '{reg}' не в allowlist"
    return True, "ok"


def storage_key(digest: str) -> str:
    """Ключ хранения OCI-архива образа в общем S3 (registry/…)."""
    if not is_valid_digest(digest):
        raise ValueError("invalid digest")
    h = digest.split(":", 1)[1]
    return f"registry/images/{h}/blob.tar"
