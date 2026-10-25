#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SLO и capacity-модель v3 (P7).

Оценка SLO по метрикам (ingest ГБ/с, время анализа, покрытие, доля Inconclusive, провалы динамики)
с выдачей алёртов; простая модель ёмкости (объём, число узлов, время ingest с учётом дедупа/overhead).
"""
from __future__ import annotations

# целевые значения (см. Arch_v3/01-requirements.md §2)
SLO = {
    "ingest_gbps": 1.0,          # на узел, минимум
    "static_seconds": 7200,      # полный статический разбор 1 ТБ
    "archive_seconds": 14400,    # разбор архива 1 ТБ
    "coverage_ratio": 0.95,
    "inconclusive_ratio_max": 0.20,
    "dynamic_fail_rate_max": 0.05,
}


def evaluate(samples: dict) -> list[dict]:
    """samples: {ingest_gbps, static_seconds, archive_seconds, coverage_ratio,
    inconclusive_ratio, dynamic_fail_rate}. Возвращает список алёртов."""
    alerts: list[dict] = []
    g = samples.get("ingest_gbps")
    if g is not None and g < SLO["ingest_gbps"] * 0.5:
        alerts.append({"alert": "ingest_below_floor", "severity": "warning",
                       "detail": f"ingest {g} < {SLO['ingest_gbps'] * 0.5}"})
    if (s := samples.get("static_seconds")) is not None and s > SLO["static_seconds"]:
        alerts.append({"alert": "static_slow", "severity": "warning", "detail": f"{s}s"})
    if (s := samples.get("archive_seconds")) is not None and s > SLO["archive_seconds"]:
        alerts.append({"alert": "archive_slow", "severity": "warning", "detail": f"{s}s"})
    if (c := samples.get("coverage_ratio")) is not None and c < SLO["coverage_ratio"]:
        alerts.append({"alert": "coverage_low", "severity": "warning", "detail": f"{c}"})
    if (r := samples.get("inconclusive_ratio")) is not None and r > SLO["inconclusive_ratio_max"]:
        alerts.append({"alert": "inconclusive_high", "severity": "warning", "detail": f"{r}"})
    if (r := samples.get("dynamic_fail_rate")) is not None and r > SLO["dynamic_fail_rate_max"]:
        alerts.append({"alert": "dynamic_fail_rate", "severity": "critical", "detail": f"{r}"})
    return alerts


def capacity(*, volume_bytes: int, throughput_gbps: float, storage_overhead: float = 1.10,
             dedup_ratio: float = 0.0, target_hours: float = 24.0) -> dict:
    """Оценка ёмкости: хранилище с overhead/дедупом и время/число узлов при заданной пропускной."""
    stored = int(volume_bytes * storage_overhead * (1.0 - max(0.0, min(dedup_ratio, 1.0))))
    per_gib = volume_bytes / (1024 ** 3)
    seconds = (volume_bytes * 8) / (throughput_gbps * 1e9) if throughput_gbps > 0 else float("inf")
    hours = seconds / 3600.0
    nodes = max(1, int((hours + target_hours - 1) // target_hours)) if hours != float("inf") else 0
    return {"stored_bytes": stored, "ingest_hours": round(hours, 2),
            "nodes_for_target": nodes, "target_hours": target_hours, "volume_gib": round(per_gib, 1)}
