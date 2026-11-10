#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""v4: плагины-зонды (`probe`) и дополнительные ассерты для раннера.

Плагин — расширяемая проверка без правки ядра: регистрируется по имени и вызывается шагом
TestPack `{"type":"probe","plugin":"<name>"}`. Плагин исполняется **в песочнице** и возвращает
список находок в единой схеме (severity/category/confidence/evidence).

Встроенные плагины — минимальные (каркас); реальные зонды подключаются регистрацией.
"""
from __future__ import annotations

from typing import Any, Callable

PLUGINS: dict[str, Callable[[dict[str, Any]], list[dict[str, Any]]]] = {}


def register(name: str):
    """Декоратор регистрации плагина: ``@register("introspect")``."""
    def _wrap(fn: Callable[[dict[str, Any]], list[dict[str, Any]]]):
        PLUGINS[name] = fn
        return fn
    return _wrap


def get(name: str):
    return PLUGINS.get(name)


def run(name: str, ctx: dict[str, Any]) -> list[dict[str, Any]]:
    """Вызвать плагин; неизвестный плагин возвращает пустой список (шаг помечается skipped)."""
    fn = PLUGINS.get(name)
    if fn is None:
        return []
    try:
        out = fn(ctx or {})
        return list(out or [])
    except Exception as exc:  # noqa: BLE001
        return [{"id": f"PLUGIN-{name}", "category": "probe", "severity": "info",
                 "confidence": 0.0, "evidence": {"error": f"{type(exc).__name__}: {exc}"}}]


def names() -> list[str]:
    return sorted(PLUGINS)


@register("introspect")
def _introspect(ctx: dict[str, Any]) -> list[dict[str, Any]]:
    """Каркас зонда: сообщить, что артефакт/движок был поднят (для трассировки покрытия)."""
    eng = ctx.get("engine_manifest") or {}
    return [{"id": "PROBE-INTROSPECT", "category": "probe", "severity": "info", "confidence": 0.1,
             "evidence": {"engine": eng.get("id") or ctx.get("engine", "")}}]
