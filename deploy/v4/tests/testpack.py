#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v4: TestPack — набор проверок как данные.

TestPack описывает **что** и **как** проверяем: список шагов (static/load/invoke/stream/
interactive/fuzz/adversarial/assert/snapshot/raw), применяемость (тип артефакта, движок),
требования к наблюдению и бюджеты. Пакет версионируется и хешируется; фиксируется в `bundle`.

Только стандартная библиотека; без побочных эффектов.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

STEP_TYPES = ("static", "load", "probe", "invoke", "stream", "interactive",
              "fuzz", "adversarial", "assert", "snapshot", "raw")

# Необязательные поля шага; обязательные зависят от типа.
_STEP_REQUIRED = {
    "invoke": ("dataset",),
    "stream": ("dataset",),
    "interactive": ("script",),
    "adversarial": ("dataset",),
    "assert": (),              # over/rules опциональны (по умолчанию responses)
    "probe": ("plugin",),
}

# Встроенные пакеты (используются, если в реестре нет своих версий).
BUILTIN_PACKS: dict[str, dict[str, Any]] = {
    "format-basic": {
        "id": "format-basic", "version": 1,
        "applies_to": {"artifact_kinds": ["safetensors", "onnx", "gguf", "hdf5", "keras"]},
        "observation": {"require": ["file", "process"]},
        "budgets": {"wall_s": 300}, "datasets": [],
        "steps": [{"type": "static"}, {"type": "load"}, {"type": "assert", "over": ["findings"]}],
    },
    "code-exec-basic": {
        "id": "code-exec-basic", "version": 1,
        "applies_to": {"artifact_kinds": ["pickle", "torch", "numpy", "script", "notebook"]},
        "observation": {"require": ["process", "network", "file"]},
        "budgets": {"wall_s": 600}, "datasets": [],
        "steps": [{"type": "static"}, {"type": "load"}, {"type": "probe", "plugin": "introspect"},
                  {"type": "assert", "over": ["findings", "events"]}],
    },
    "container-basic": {
        "id": "container-basic", "version": 1,
        "applies_to": {"artifact_kinds": ["archive", "dataset"]},
        "observation": {"require": ["file", "process"]},
        "budgets": {"wall_s": 600}, "datasets": [],
        "steps": [{"type": "static"}, {"type": "load"}, {"type": "assert", "over": ["findings"]}],
    },
    "llm-basic": {
        "id": "llm-basic", "version": 1,
        "applies_to": {"artifact_kinds": ["llm-gguf", "llm-safetensors", "gguf"], "engines": ["kind:llm"]},
        "observation": {"require": ["process", "network"]},
        "budgets": {"wall_s": 900, "tokens": 20000}, "datasets": [{"id": "benign", "ref": "ds://prompts/benign@1"}],
        "steps": [{"type": "load"},
                  {"type": "invoke", "dataset": "benign", "params": {"max_tokens": 64}},
                  {"type": "assert", "over": ["responses"]}],
    },
    "llm-safety": {
        "id": "llm-safety", "version": 1,
        "applies_to": {"artifact_kinds": ["llm-gguf", "llm-safetensors", "gguf"], "engines": ["kind:llm"]},
        "observation": {"require": ["process", "network", "file"]},
        "budgets": {"wall_s": 3600, "tokens": 400000},
        "datasets": [{"id": "benign", "ref": "ds://prompts/benign@1"},
                     {"id": "redteam", "ref": "ds://prompts/redteam@1"}],
        "steps": [{"type": "load"},
                  {"type": "invoke", "dataset": "benign", "params": {"max_tokens": 64}},
                  {"type": "invoke", "dataset": "redteam", "params": {"max_tokens": 64}},
                  {"type": "interactive", "script": "ds://scripts/tool-call-basic@1"},
                  {"type": "assert", "over": ["responses", "findings", "events"]}],
    },
}


def _canonical(pack: dict[str, Any]) -> bytes:
    return json.dumps(pack, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def pack_hash(pack: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(_canonical(pack)).hexdigest()


def validate_pack(pack: dict[str, Any]) -> list[str]:
    """Вернуть список проблем (пусто — валидно). Ничего не бросает."""
    errs: list[str] = []
    if not isinstance(pack, dict):
        return ["pack must be an object"]
    if not pack.get("id"):
        errs.append("id is required")
    try:
        if int(pack.get("version", 0)) < 1:
            errs.append("version must be >= 1")
    except (TypeError, ValueError):
        errs.append("version must be an integer")
    steps = pack.get("steps")
    if not isinstance(steps, list) or not steps:
        errs.append("steps must be a non-empty list")
    else:
        for i, st in enumerate(steps):
            if not isinstance(st, dict):
                errs.append(f"step#{i} must be an object"); continue
            t = st.get("type")
            if t not in STEP_TYPES:
                errs.append(f"step#{i} unknown type {t!r}")
                continue
            for req in _STEP_REQUIRED.get(t, ()):
                if not st.get(req):
                    errs.append(f"step#{i} ({t}) requires {req!r}")
    ap = pack.get("applies_to")
    if ap is not None and not isinstance(ap, dict):
        errs.append("applies_to must be an object")
    obs = pack.get("observation")
    if obs is not None and not isinstance(obs, dict):
        errs.append("observation must be an object")
    if pack.get("budgets") is not None and not isinstance(pack["budgets"], dict):
        errs.append("budgets must be an object")
    if pack.get("datasets") is not None and not isinstance(pack["datasets"], list):
        errs.append("datasets must be a list")
    return errs


def compile_pack(pack: dict[str, Any]) -> dict[str, Any]:
    """Проверить пакет (fail-fast) и вернуть нормализованную копию с `hash`."""
    errs = validate_pack(pack)
    if errs:
        raise ValueError("invalid TestPack: " + "; ".join(errs))
    out = json.loads(json.dumps(pack))          # глубокая копия
    out["version"] = int(out.get("version", 1))
    out.setdefault("applies_to", {})
    out.setdefault("observation", {"require": []})
    out.setdefault("budgets", {})
    out.setdefault("datasets", [])
    out["hash"] = pack_hash({k: v for k, v in out.items() if k != "hash"})
    return out


def _engine_matches(tokens: list[str], engine: str) -> bool:
    e = (engine or "").lower()
    for t in tokens or []:
        t = str(t).lower()
        if t.startswith("kind:"):
            if t[5:] in e:
                return True
        elif t and t in e:
            return True
    return False


def matches(pack: dict[str, Any], *, artifact_kind: str | None = None, engine: str | None = None) -> bool:
    """Подходит ли пакет под (тип артефакта, движок). Пустые ограничения — «любой»."""
    ap = pack.get("applies_to") or {}
    kinds = [k.lower() for k in (ap.get("artifact_kinds") or [])]
    if artifact_kind and kinds:
        ak = artifact_kind.lower()
        if ak in kinds:
            pass
        elif ak.startswith("llm-"):
            # llm-пакет применим к llm-* типам
            if not any(k.startswith("llm-") for k in kinds):
                return False
        else:
            # generic-артефакт: применим generic-пакет или llm-пакет с llm-<base>
            if not any(k == "llm-" + ak for k in kinds):
                return False
    engs = ap.get("engines") or []
    if engine and engs and not _engine_matches(engs, engine):
        return False
    return True


def select_packs(packs: list[dict[str, Any]], *, artifact_kind: str | None = None,
                 engine: str | None = None) -> list[dict[str, Any]]:
    return [p for p in packs if matches(p, artifact_kind=artifact_kind, engine=engine)]


def all_builtin() -> list[dict[str, Any]]:
    return [compile_pack(dict(p)) for p in BUILTIN_PACKS.values()]
