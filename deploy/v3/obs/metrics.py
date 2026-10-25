#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Метрики v3 (P7): реестр с метками (per-tenant) и Prometheus-экспозиция.

Лёгкая, потокобезопасная реализация без внешних зависимостей: counter/gauge/histogram-lite.
Метка `tenant` позволяет отдавать per-tenant метрики ingest/анализа/вердиктов.
"""
from __future__ import annotations

import threading


def _fmt_labels(labels: dict | None) -> str:
    if not labels:
        return ""
    items = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
    return "{" + items + "}"


class Registry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._series: dict[tuple, dict] = {}

    def _key(self, name: str, kind: str, labels: dict | None):
        return (name, kind, tuple(sorted((labels or {}).items())))

    def inc(self, name: str, labels: dict | None = None, value: float = 1.0) -> None:
        with self._lock:
            k = self._key(name, "counter", labels)
            s = self._series.setdefault(k, {"v": 0.0})
            s["v"] += float(value)

    def set(self, name: str, value: float, labels: dict | None = None) -> None:  # noqa: A003
        with self._lock:
            k = self._key(name, "gauge", labels)
            self._series[k] = {"v": float(value)}

    def observe(self, name: str, value: float, labels: dict | None = None) -> None:
        with self._lock:
            k = self._key(name, "hist", labels)
            s = self._series.setdefault(k, {"count": 0, "sum": 0.0})
            s["count"] += 1
            s["sum"] += float(value)

    def get(self, name: str, labels: dict | None = None, kind: str = "counter") -> float:
        with self._lock:
            s = self._series.get(self._key(name, kind, labels))
            return float(s["v"]) if s and "v" in s else 0.0

    def render(self) -> str:
        lines = []
        with self._lock:
            for (name, kind, labels) in sorted(self._series, key=lambda x: (x[0], x[2])):
                s = self._series[(name, kind, labels)]
                lbl = _fmt_labels(dict(labels))
                if kind == "hist":
                    lines.append(f"{name}_count{lbl} {s['count']}")
                    lines.append(f"{name}_sum{lbl} {s['sum']}")
                else:
                    lines.append(f"{name}{lbl} {s['v']}")
        return "\n".join(lines) + ("\n" if lines else "")
