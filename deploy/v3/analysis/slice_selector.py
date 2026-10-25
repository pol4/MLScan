#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Детерминированный selector срезов для сэмплированной динамики (v3, P5).

Для крупных объектов динамика запускается не на всём файле, а на **срезах** (head/tail/стратифицированные
точки), укладывающихся в бюджет. Selector детерминирован (seed) и возвращает план диапазонов +
оценку покрытия (доля байт, попадающих в анализ).
"""
from __future__ import annotations

import hashlib

DEFAULT = {"max_slice_bytes": 64 * 1024 ** 2, "max_slices": 8,
           "head_bytes": 1 * 1024 ** 2, "tail_bytes": 1 * 1024 ** 2}


def _seed_offset(seed: int, i: int, span: int) -> int:
    h = hashlib.sha256(f"{seed}:{i}".encode()).digest()
    return int.from_bytes(h[:8], "big") % max(span, 1)


def select_slices(total_size: int, *, max_slice_bytes: int = DEFAULT["max_slice_bytes"],
                  max_slices: int = DEFAULT["max_slices"], head_bytes: int = DEFAULT["head_bytes"],
                  tail_bytes: int = DEFAULT["tail_bytes"], seed: int = 0,
                  stratify: bool = True) -> dict:
    """План срезов. Возвращает {slices, covered_bytes, coverage_ratio, budget, deterministic_seed}."""
    if total_size <= 0:
        return {"slices": [], "covered_bytes": 0, "coverage_ratio": 0.0,
                "budget": {"max_slice_bytes": max_slice_bytes, "max_slices": max_slices},
                "deterministic_seed": seed}
    if total_size <= max_slice_bytes * max_slices:
        return {"slices": [{"offset": 0, "length": total_size, "kind": "full"}],
                "covered_bytes": total_size, "coverage_ratio": 1.0,
                "budget": {"max_slice_bytes": max_slice_bytes, "max_slices": max_slices},
                "deterministic_seed": seed}

    slices: list[dict] = []
    covered = 0
    # head/tail — «дорогие» по информации участки (заголовок/индекс/хвост)
    head = min(head_bytes, max_slice_bytes, total_size)
    slices.append({"offset": 0, "length": head, "kind": "head"})
    covered += head
    tail = min(tail_bytes, max_slice_bytes, total_size - head)
    if tail > 0:
        slices.append({"offset": total_size - tail, "length": tail, "kind": "tail"})
        covered += tail

    remaining = max(max_slices - len(slices), 0)
    if stratify and remaining > 0:
        span = max(total_size - head - tail, 1)
        for i in range(remaining):
            length = min(max_slice_bytes, max(total_size // (remaining + 1), 1))
            base = head + (span * (i + 1)) // (remaining + 1)
            off = base + (_seed_offset(seed, i, max(span // (remaining + 2), 1))
                          if seed else 0)
            off = max(head, min(off, total_size - length))
            slices.append({"offset": off, "length": length, "kind": f"strat-{i}"})
            covered += length
    # не выходим за бюджет по числу
    slices = slices[:max_slices]
    covered = min(sum(s["length"] for s in slices), total_size)
    return {"slices": slices, "covered_bytes": covered,
            "coverage_ratio": round(covered / total_size, 6),
            "budget": {"max_slice_bytes": max_slice_bytes, "max_slices": max_slices},
            "deterministic_seed": seed}


def select_members_for_dynamic(members: list[dict], *, max_member_bytes: int = 512 * 1024 ** 2,
                               max_count: int = 16, priority_exts=(".pkl", ".pt", ".pth", ".bin",
                                                                    ".safetensors", ".onnx", ".gguf")) -> list[dict]:
    """Выбрать членов архива для динамики: сначала исполняемые форматы и малые по размеру."""
    def rank(m: dict) -> tuple:
        name = str(m.get("name", "")).lower()
        prio = 0 if any(name.endswith(e) for e in priority_exts) else 1
        size = int(m.get("uncompressed") or m.get("compressed") or 0)
        return (prio, size, name)
    ok = [m for m in members if not m.get("skip_reason")
          and int(m.get("uncompressed") or m.get("compressed") or 0) <= max_member_bytes]
    return sorted(ok, key=rank)[:max_count]
