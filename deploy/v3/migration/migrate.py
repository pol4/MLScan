#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Миграция v2 → v3 (P9): план переноса объектов в общий пул, refs, реконсиляция, готовность.

- v2-ключи (`sha256/<name>`, `tenant/<t>/<sha>/<name>`) → v3-ключ общего пула `objects/<aa>/<bb>/<sha>`
  (server-side copy, идемпотентно; дедуп по содержимому).
- Реконсиляция: сверка множеств sha (v2-артефакты vs v3-refs) → missing/extra.
- Готовность cutover по чек-листу (объекты, refs, evidence, SLO).
"""
from __future__ import annotations

import sys

sys.path.insert(0, "/opt/v3ingest")
try:
    from pool import pool_key  # type: ignore
except Exception:  # noqa: BLE001
    pool_key = None  # type: ignore


def dst_key(sha: str, tenant: str = "") -> str:
    if pool_key is not None:
        return pool_key(sha)
    return f"objects/{sha[:2]}/{sha[2:4]}/{sha}"


def plan_object_migration(rows: list[dict]) -> list[dict]:
    """rows: [{key|s3_key, sha256, tenant, name?, size?}] → план {src_key,dst_key,sha,tenant,size}."""
    plan = []
    for r in rows or []:
        sha = (r.get("sha256") or "").lower()
        src = r.get("s3_key") or r.get("key") or ""
        if not sha or not src:
            continue
        plan.append({"src_key": src, "dst_key": dst_key(sha, r.get("tenant", "")), "sha256": sha,
                     "tenant": r.get("tenant", ""), "name": r.get("name", ""),
                     "size": int(r.get("size") or 0)})
    return plan


def reconcile(v2_hashes, v3_refs) -> dict:
    """Сверка множеств sha256 (v2-артефакты vs v3 object_refs)."""
    a = {str(x).lower() for x in (v2_hashes or [])}
    b = {str(x).lower() for x in (v3_refs or [])}
    missing = sorted(a - b)
    extra = sorted(b - a)
    return {"v2_count": len(a), "v3_count": len(b), "missing_in_v3": missing,
            "extra_in_v3": extra, "ok": not missing}


def readiness(checks: dict) -> tuple[bool, list[str]]:
    """checks: {objects_migrated, refs_ok, evidence_verified, slo_ok, no_v2_writes}."""
    required = ("objects_migrated", "refs_ok", "evidence_verified", "no_v2_writes")
    reasons = [k for k in required if not checks.get(k)]
    if checks.get("slo_ok") is False:
        reasons.append("slo_not_met")
    return (not reasons), reasons
