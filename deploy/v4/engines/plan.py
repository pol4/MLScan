#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v4: сборка «плана проверки» — движок + пакеты тестов + наблюдение + политика.

План детерминированно связывает: дескриптор движка (и выбранный RuntimeClass-профиль Kata),
подобранные `TestPack` (кто уже отфильтровал по типу артефакта/движку), требования наблюдения
(объединение) и версию политики вердикта. План фиксируется в записи теста (bundle_tests) и
отдаётся API — это «мост» между декларативными тестами и запуском Job'а.
"""
from __future__ import annotations

from typing import Any, Iterable

from . import descriptor as _ed


def _union_observation(packs: Iterable[dict[str, Any]]) -> list[str]:
    out: list[str] = []
    for p in packs or []:
        for r in (p.get("observation") or {}).get("require") or []:
            r = str(r)
            if r and r not in out:
                out.append(r)
    return out


def build_plan(desc: _ed.EngineDescriptor, packs: list[dict[str, Any]], *,
               artifact_kind: str = "", engine: str = "", policy: dict[str, Any] | None = None,
               available: Iterable[str] | None = None, gpu_available: bool = False,
               allow_cpu_fallback: bool = True, actual_runtime_class: str = "") -> dict[str, Any]:
    """Собрать план проверки.

    ``packs`` — уже отобранные пакеты (см. ``tests.testpack.select_packs``). RuntimeClass выбирается
    по дескриптору (только Kata-профили; при нехватке GPU — деградация или отказ).
    """
    try:
        rc = _ed.plan_runtime_class(desc, available=available, gpu_available=gpu_available,
                                    allow_cpu_fallback=allow_cpu_fallback)
    except RuntimeError as exc:
        rc = {"runtime_class": "", "degraded": True, "reason": str(exc)}
    return {
        "engine": {
            "id": desc.id, "kind": desc.kind, "oci": desc.oci,
            "runtime_class": rc.get("runtime_class", ""),
            "actual_runtime_class": actual_runtime_class or "",
            "host_execution": (actual_runtime_class or "").lower() in ("nvidia", "runc"),
            "degraded": bool(rc.get("degraded")),
            "reason": rc.get("reason", ""),
            "resources": desc.resource_profile(),
            "protocols": desc.protocols(),
        },
        "testpacks": [{
            "id": p.get("id"), "version": p.get("version"), "hash": p.get("hash"),
            "steps": [s.get("type") for s in (p.get("steps") or [])],
            "observation": p.get("observation"), "budgets": p.get("budgets"),
        } for p in packs or []],
        "observation": {"require": _union_observation(packs or [])},
        "policy": dict(policy or {}),
        "artifact_kind": artifact_kind,
        "engine_ref": engine,
    }
