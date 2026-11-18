#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v4: запись/реплей прогонов TestPack в «кассеты» (T5).

Кассета — детерминированный снимок ответов движка: она привязывает каждый вызов
(`invoke`/`load`/`probe`/…, ключ = хеш `(op, request)`) к его результату. Это даёт
**реплей без движка** — обязательную основу для симулятора/бэктеста (P3) и unit-тестов:
один и тот же TestPack прогоняется повторно с идентичным результатом, без GPU и сети.

Инварианты:
  * ключ записи — ``sha256`` канонического ``{"op", "req"}`` (стабилен между прогонами);
  * реплей по умолчанию **строгий** (fail-closed): нет записи ⇒ `CassetteMiss`, а не тихий пустой ответ;
  * `input_hash` фиксирует множество запросов — для проверки «та же выборка» при реплее.

Только стандартная библиотека; модуль без побочных эффектов.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

CASSETTE_FORMAT = "mlscan/v4/cassette@1"

# Операции движка, которые записываются/воспроизводятся (совпадают с интерфейсом tests.runner).
_OPS = ("health", "static", "load", "control", "probe", "manifest", "snapshot", "invoke", "raw")

_MISS = object()


def _canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _op_request(op: str, args: tuple, kwargs: dict) -> Any:
    """Канонизировать запрос операции: первый позиционный аргумент (или kwargs), иначе {}."""
    if args:
        return {"args": list(args), "kwargs": kwargs} if kwargs else args[0]
    return kwargs or {}


class CassetteMiss(RuntimeError):
    """Нет записи в кассете для запрошенной операции (строгий реплей)."""


class Cassette:
    """Набор записей ответов движка (op, req) → result."""

    def __init__(self, meta: dict[str, Any] | None = None,
                 entries: dict[str, dict[str, Any]] | None = None):
        self.meta: dict[str, Any] = dict(meta or {})
        self.entries: dict[str, dict[str, Any]] = dict(entries or {})

    # ---- ключи и записи --------------------------------------------------
    @staticmethod
    def key(op: str, req: Any) -> str:
        return hashlib.sha256(_canon({"op": op, "req": req}).encode("utf-8")).hexdigest()

    def record(self, op: str, req: Any, result: Any) -> str:
        k = self.key(op, req)
        self.entries[k] = {"op": op, "req": req, "result": result}
        return k

    def lookup(self, op: str, req: Any) -> Any:
        return self.entries.get(self.key(op, req), _MISS)

    def __len__(self) -> int:
        return len(self.entries)

    def __contains__(self, item: tuple) -> bool:  # (op, req)
        try:
            op, req = item
        except (TypeError, ValueError):
            return False
        return self.lookup(op, req) is not _MISS

    # ---- целостность -----------------------------------------------------
    def input_hash(self) -> str:
        """Хеш множества запросов (без результатов) — проверка «та же выборка»."""
        reqs = sorted(_canon({"op": e.get("op"), "req": e.get("req")}) for e in self.entries.values())
        return "sha256:" + hashlib.sha256(_canon(reqs).encode("utf-8")).hexdigest()

    # ---- сериализация ----------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        meta = dict(self.meta)
        meta.setdefault("format", CASSETTE_FORMAT)
        meta["count"] = len(self.entries)
        meta["input_hash"] = self.input_hash()
        return {"meta": meta, "entries": self.entries}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Cassette":
        obj = d or {}
        return cls(meta=obj.get("meta") or {}, entries=obj.get("entries") or {})

    def save(self, path: str) -> str:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, ensure_ascii=False, sort_keys=True, indent=1)
        return path

    @classmethod
    def load(cls, path: str) -> "Cassette":
        with open(path, "r", encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh))


class RecordingEngine:
    """Обёртка над реальным движком: прозрачно проксирует и пишет ответы в кассету.

    Методы повторяют интерфейс движка (см. `tests.runner`); определяются **только** если они
    есть у inner — чтобы `runner` видел ровно те возможности, что и без обёртки.
    """

    def __init__(self, inner: Any, cassette: Cassette):
        self._inner = inner
        self.cassette = cassette
        for op in _OPS:
            if hasattr(inner, op):
                setattr(self, op, self._wrap(op))

    def _wrap(self, op: str):
        def call(*args, **kwargs):
            res = getattr(self._inner, op)(*args, **kwargs)
            self.cassette.record(op, _op_request(op, args, kwargs), res)
            return res
        call.__name__ = op
        return call


class ReplayEngine:
    """Движок, отдающий ответы из кассеты (без реального движка/сети/GPU).

    `strict=True` (по умолчанию) — fail-closed: отсутствие записи ⇒ `CassetteMiss`.
    `strict=False` — отдаёт безопасный пустой ответ (для «мягкого» реплея).
    """

    def __init__(self, cassette: Cassette, *, strict: bool = True):
        self.cassette = cassette
        self.strict = bool(strict)

    def _serve(self, op: str, req: Any) -> Any:
        e = self.cassette.lookup(op, req)
        if e is not _MISS:
            return e.get("result")
        if self.strict:
            raise CassetteMiss(f"нет записи в кассете: op={op}")
        return {"text": "", "usage": {}} if op == "invoke" else None

    def health(self) -> bool:
        return True

    def static(self):
        return self._serve("static", {})

    def load(self):
        return self._serve("load", {})

    def manifest(self):
        return self._serve("manifest", {})

    def snapshot(self):
        return self._serve("snapshot", {})

    def control(self, action: str, params: dict[str, Any] | None = None):
        return self._serve("control", {"action": action, "params": params or {}})

    def probe(self, plugin: str):
        return self._serve("probe", {"plugin": plugin})

    def invoke(self, req: dict[str, Any]):
        return self._serve("invoke", req)

    def raw(self, step: dict[str, Any]):
        return self._serve("raw", step)


def record_run(pack: dict[str, Any], engine: Any, datasets: Any, *, observer: Any = None,
               budgets: dict[str, Any] | None = None, clock=None) -> tuple[dict[str, Any], Cassette]:
    """Прогнать TestPack на реальном движке и записать ответы в кассету.

    Возвращает `(result, cassette)`; `result` — как у `runner.run_pack`.
    """
    from . import runner as runner_mod
    cassette = Cassette(meta={"pack_id": (pack or {}).get("id"),
                              "pack_version": (pack or {}).get("version")})
    rec = RecordingEngine(engine, cassette)
    kwargs: dict[str, Any] = {"observer": observer}
    if budgets is not None:
        kwargs["budgets"] = budgets
    if clock is not None:
        kwargs["clock"] = clock
    result = runner_mod.run_pack(pack, rec, datasets, **kwargs)
    return result, cassette


def replay_run(pack: dict[str, Any], cassette: Cassette, datasets: Any, *, observer: Any = None,
               budgets: dict[str, Any] | None = None, clock=None, strict: bool = True) -> dict[str, Any]:
    """Воспроизвести прогон из кассеты без движка (детерминированно)."""
    from . import runner as runner_mod
    eng = ReplayEngine(cassette, strict=strict)
    kwargs: dict[str, Any] = {"observer": observer}
    if budgets is not None:
        kwargs["budgets"] = budgets
    if clock is not None:
        kwargs["clock"] = clock
    return runner_mod.run_pack(pack, eng, datasets, **kwargs)


def case_from_result(result: dict[str, Any], *, label: str | None = None,
                     profile: str | None = None, case_id: str | None = None) -> dict[str, Any]:
    """Преобразовать результат прогона в кейс для симулятора политики (P3/бэктест).

    Мост T5→P3: записанный прогон (или его реплей) становится кейсом `scoring.simulator`.
    """
    r = result or {}
    case: dict[str, Any] = {"findings": list(r.get("findings") or []),
                            "coverage": r.get("coverage") or {},
                            "results": r.get("results") or {}}
    cid = case_id if case_id is not None else (r.get("pack") or {}).get("id")
    if cid is not None:
        case["id"] = cid
    if profile:
        case["profile"] = profile
    if label in ("safe", "unsafe"):
        case["label"] = label
    return case
