#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Оркестратор сканов (v3, P2): выбор стратегии анализа по типу/формату/размеру.

Чистая функция: по `kind` (артефакт), формату, размеру и лимиту динамики выбирает стратегию
(`llm-inference` | `archive` | `dynamic` | `static`) и бюджеты. Используется при постановке скана
в очередь и воркерами анализа.
"""
from __future__ import annotations

ARCHIVE_EXTS = (".zip", ".tar", ".tgz", ".tar.gz", ".gz", ".bz2", ".xz", ".7z", ".rar")
LLM_ARCHES = ("llama", "qwen", "mistral", "mixtral", "gpt2", "gptj", "gemma", "phi", "falcon")


def choose_strategy(*, kind: str = "model", fmt: str = "", size: int = 0,
                    dynamic_max_bytes: int = 6 * 1024 ** 3,
                    is_llm: bool = False, has_engine_image: bool = False) -> dict:
    """Вернуть {'strategy':..., 'dynamic': bool, 'reason':...}."""
    k = (kind or "model").lower()
    f = (fmt or "").lower()
    if k == "engine_image":
        return {"strategy": "static", "dynamic": False, "reason": "engine image: только скан образа"}
    if k == "archive" or any(f.endswith(e) for e in ARCHIVE_EXTS):
        return {"strategy": "archive", "dynamic": size <= dynamic_max_bytes,
                "reason": "архив: членный обход"}
    if is_llm and has_engine_image:
        return {"strategy": "llm-inference", "dynamic": True,
                "reason": "LLM + образ движка: запуск инференса в песочнице"}
    if is_llm and not has_engine_image:
        return {"strategy": "static", "dynamic": False,
                "reason": "LLM без образа движка: только статика (нужен binding)"}
    if size <= dynamic_max_bytes:
        return {"strategy": "dynamic", "dynamic": True, "reason": "объект в лимитах песочницы"}
    return {"strategy": "static", "dynamic": False, "reason": "крупный объект: static-only"}
