#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v4: Dataset — версионированные тестовые данные (prompts/inputs/fuzz/expected).

Адресация: ``ds://<kind>/<name>@<version>`` (например, ``ds://prompts/redteam-ru@4``).
Провайдер (`DatasetRepo`) отдаёт кейсы по ссылке; хранение — вне модуля (БД/S3), здесь —
парсинг ссылок, хеширование и in-memory провайдер для тестов.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Callable


def parse_ref(ref: str) -> dict[str, Any]:
    """Разобрать ссылку датасета ``ds://kind/name@version``."""
    s = (ref or "").strip()
    if not s.startswith("ds://"):
        raise ValueError(f"bad dataset ref: {ref!r}")
    body = s[len("ds://"):]
    ver = None
    if "@" in body:
        body, v = body.rsplit("@", 1)
        try:
            ver = int(v)
        except ValueError as exc:
            raise ValueError(f"bad dataset version in {ref!r}") from exc
    parts = [p for p in body.split("/") if p]
    if len(parts) < 2:
        raise ValueError(f"bad dataset ref (want ds://kind/name@ver): {ref!r}")
    return {"kind": parts[0], "name": "/".join(parts[1:]), "version": ver, "ref": s}


def make_ref(kind: str, name: str, version: int) -> str:
    return f"ds://{kind}/{name}@{int(version)}"


def dataset_hash(cases: list[dict[str, Any]]) -> str:
    canon = json.dumps(cases or [], sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(canon).hexdigest()


class DatasetRepo:
    """In-memory провайдер датасетов: ``fetch(ref) -> list[case]``.

    В стенде заменяется провайдером из БД/artifact gateway с той же сигнатурой.
    """

    def __init__(self, data: dict[str, list[dict[str, Any]]] | None = None,
                 fetch_fn: Callable[[str], list[dict[str, Any]]] | None = None):
        self._data = dict(data or {})
        self._fetch_fn = fetch_fn

    def register(self, ref: str, cases: list[dict[str, Any]]) -> None:
        parse_ref(ref)                       # валидация ссылки
        self._data[ref] = list(cases or [])

    def fetch(self, ref: str) -> list[dict[str, Any]]:
        if self._fetch_fn is not None:
            cases = self._fetch_fn(ref)
            if cases is not None:
                return list(cases)
        if ref in self._data:
            return list(self._data[ref])
        # допускаем ссылки без версии — ищем любой подходящий по kind/name
        try:
            want = parse_ref(ref)
        except ValueError:
            return []
        for k, v in self._data.items():
            try:
                have = parse_ref(k)
            except ValueError:
                continue
            if have["kind"] == want["kind"] and have["name"] == want["name"]:
                return list(v)
        return []

    def list_refs(self) -> list[dict[str, Any]]:
        out = []
        for ref, cases in self._data.items():
            try:
                meta = parse_ref(ref)
            except ValueError:
                continue
            out.append({"ref": ref, "kind": meta["kind"], "name": meta["name"],
                        "version": meta["version"], "cases": len(cases), "hash": dataset_hash(cases)})
        return sorted(out, key=lambda x: x["ref"])
