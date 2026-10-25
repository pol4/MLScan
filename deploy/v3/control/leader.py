#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Single-writer / leader-election (v3, P8) на PostgreSQL advisory-lock.

Гарантирует «один писатель» для критичных операций (evidence, lifecycle, attestation) при
нескольких репликах: владелец — тот, кто взял advisory-lock; остальные — follower. Освобождение
(или разрыв соединения) отдаёт роль следующему. Настоящий HA между узлами/сайтами — на целевом
железе (см. `Arch_v3/10-deployment.md`).
"""
from __future__ import annotations


def _lit(v) -> str:
    return "'" + str(v).replace("'", "''") + "'"


def _rows(res):
    """Поддержать обе формы: [(...)] (список строк) и (columns, rows) (pgclient)."""
    if isinstance(res, tuple) and len(res) == 2 and isinstance(res[1], list):
        return res[1]
    return res or []


def _truthy(v) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v != 0
    return str(v).strip().lower() in ("t", "true", "1", "yes", "on")


def lock_id(name: str) -> int:
    import hashlib
    return int.from_bytes(hashlib.sha256(name.encode()).digest()[:8], "big") & 0x7FFFFFFFFFFFFFFF


class Leader:
    """Обёртка над advisory-lock. db_query/db_exec — внедряемые (тестируемость)."""

    def __init__(self, name: str, db_query, db_exec, owner: str = "") -> None:
        self.name = name
        self._id = lock_id(name)
        self._q = db_query
        self._e = db_exec
        self.owner = owner
        self._held = False

    def acquire(self) -> bool:
        rows = _rows(self._q(f"SELECT pg_try_advisory_lock({self._id})"))
        ok = _truthy(rows[0][0]) if (rows and rows[0]) else False
        self._held = ok
        return ok

    def release(self) -> None:
        try:
            self._e(f"SELECT pg_advisory_unlock({self._id})")
        finally:
            self._held = False

    def is_leader(self) -> bool:
        return self._held

    def hold_key(self) -> str:
        return f"mlscan:leader:{self.name}"
