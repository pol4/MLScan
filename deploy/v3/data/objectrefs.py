#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Ссылки тенантов на объекты общего пула (v3, P0).

Модель: физический объект хранится один раз (content-addressed, `pool.py`), а тенанты держат
ссылки `object_refs(tenant_id, sha256, name, size, refcount)`. Объект удаляется (GC) только когда
`refcount = 0`. Изоляция доступа — на уровне API (тенант видит только свои ссылки).
"""
from __future__ import annotations

from pool import is_sha256  # type: ignore


def _lit(v) -> str:
    if v is None:
        return "NULL"
    if isinstance(v, (int, float)):
        return str(v)
    return "'" + str(v).replace("'", "''") + "'"


# DDL — часть общей схемы v3 (deploy/v3/db/schema-v3.sql)
DDL_OBJECT_REFS = """
CREATE TABLE IF NOT EXISTS object_refs (
  id BIGSERIAL PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  sha256 TEXT NOT NULL,
  name TEXT,
  size BIGINT,
  refcount INT NOT NULL DEFAULT 1,
  first_seen TIMESTAMPTZ DEFAULT now(),
  last_seen TIMESTAMPTZ DEFAULT now(),
  UNIQUE (tenant_id, sha256)
);
CREATE INDEX IF NOT EXISTS idx_object_refs_sha ON object_refs(sha256);
CREATE INDEX IF NOT EXISTS idx_object_refs_tenant ON object_refs(tenant_id);
""".strip()


def ref_add_sql(tenant: str, sha256: str, name: str = "", size: int = 0) -> str:
    """Добавить/обновить ссылку тенанта; повторная ссылка увеличивает refcount."""
    if not is_sha256(sha256):
        raise ValueError("sha256 must be 64 lowercase hex chars")
    if not tenant:
        raise ValueError("tenant is required")
    return (
        "INSERT INTO object_refs(tenant_id, sha256, name, size, refcount) VALUES "
        f"({_lit(tenant)},{_lit(sha256.lower())},{_lit(name)},{int(size)},1) "
        "ON CONFLICT (tenant_id, sha256) DO UPDATE SET "
        "refcount = object_refs.refcount + 1, last_seen = now(), "
        "name = COALESCE(NULLIF(EXCLUDED.name,''), object_refs.name), "
        "size = GREATEST(object_refs.size, EXCLUDED.size) "
        "RETURNING refcount"
    )


def ref_del_sql(tenant: str, sha256: str) -> str:
    """Удалить ссылку тенанта (уменьшить refcount); возвращает остаток refcount (0 = можно GC)."""
    if not is_sha256(sha256):
        raise ValueError("sha256 must be 64 lowercase hex chars")
    if not tenant:
        raise ValueError("tenant is required")
    return (
        "UPDATE object_refs SET refcount = refcount - 1, last_seen = now() "
        f"WHERE tenant_id={_lit(tenant)} AND sha256={_lit(sha256.lower())} "
        "AND refcount > 0 RETURNING refcount"
    )


def ref_drop_sql(tenant: str, sha256: str) -> str:
    return (
        "DELETE FROM object_refs "
        f"WHERE tenant_id={_lit(tenant)} AND sha256={_lit(sha256.lower())}"
    )


def ref_count_sql(sha256: str) -> str:
    if not is_sha256(sha256):
        raise ValueError("sha256 must be 64 lowercase hex chars")
    return f"SELECT COALESCE(SUM(refcount),0) FROM object_refs WHERE sha256={_lit(sha256.lower())}"


def list_refs_sql(tenant: str) -> str:
    if not tenant:
        raise ValueError("tenant is required")
    return ("SELECT sha256, name, size, refcount, first_seen, last_seen FROM object_refs "
            f"WHERE tenant_id={_lit(tenant)} ORDER BY last_seen DESC")
