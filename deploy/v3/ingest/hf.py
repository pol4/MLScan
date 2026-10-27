#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Hugging Face: выбор файлов/квантизации, фильтры поиска и план докачки (v3, H1).

Чистые функции (без сети): выбор GGUF-файлов нужной квантизации, фильтрация результатов поиска
(тип/вендор/название/квантизация) и расчёт плана возобновления загрузки (Range/ETag).
Сетевую часть (search/download в фоне) реализует серверная задача-воркер.
"""
from __future__ import annotations

import re

QUANT_RE = re.compile(r"(Q\d(?:_[A-Z0-9]+)+|IQ\d(?:_[A-Z0-9]+)+|F16|FP16|BF16|F32|FP32)", re.I)
QUANT_PRIORITY = ["Q4_K_M", "Q5_K_M", "Q4_K_S", "Q5_K_S", "Q8_0", "Q6_K", "F16", "FP16", "F32", "FP32"]


def parse_quantization(filename: str) -> str:
    m = QUANT_RE.search(filename or "")
    return m.group(1).upper() if m else ""


def select_files(files: list[str], *, quantization: str = "", prefer_ext=(".gguf",)) -> list[str]:
    """Выбрать файлы: при заданной квантизации — только matching; иначе GGUF по приоритету квантизаций."""
    quant = (quantization or "").upper()
    cand = [f for f in files or [] if f.lower().endswith(tuple(prefer_ext))] or list(files or [])
    if quant:
        sel = [f for f in cand if parse_quantization(f) == quant]
        return sorted(sel) or sorted(cand)
    def rank(f: str) -> tuple:
        q = parse_quantization(f)
        return (QUANT_PRIORITY.index(q) if q in QUANT_PRIORITY else len(QUANT_PRIORITY),
                len(f), f)
    return sorted(cand, key=rank)


def filter_search(items: list[dict], *, type_: str = "", vendor: str = "", name: str = "",
                  quantization: str = "") -> list[dict]:
    """Фильтр результатов поиска HF по типу, вендору/автору, названию и квантизации (в тегах/файлах)."""
    out = []
    t, v, n, q = (type_ or "").lower(), (vendor or "").lower(), (name or "").lower(), (quantization or "").upper()
    for it in items or []:
        rid = str(it.get("id") or it.get("repo_id") or "")
        tags = " ".join(str(x) for x in (it.get("tags") or [])).lower()
        files = it.get("files") or []
        if t and t not in tags and t not in rid.lower():
            continue
        if v and not rid.lower().startswith(v + "/") and v not in tags:
            continue
        if n and n not in rid.lower():
            continue
        if q and q not in {parse_quantization(f) for f in files} and q.lower() not in tags:
            continue
        out.append(it)
    return out


def resume_plan(total_bytes: int, done_bytes: int, etag: str = "", served_etag: str = "") -> dict:
    """План докачки: если ETag совпал — продолжаем с done (Range), иначе перезагрузка с нуля."""
    total = max(int(total_bytes or 0), 0)
    done = max(int(done_bytes or 0), 0)
    restart = bool(etag and served_etag and etag != served_etag)
    if restart or done > total:
        done = 0
    return {"offset": done, "range_header": f"bytes={done}-" if done > 0 else "",
            "remaining": max(total - done, 0), "restart": restart,
            "if_range": etag and not restart, "done": restart is False and done >= total and total > 0}


def check_limits(size: int, done_bytes: int = 0, *, max_file: int = 0, max_total: int = 0) -> tuple[bool, str]:
    """Проверка пределов загрузки HF (fail-closed для неизвестного размера).

    size: размер файла (0 = неизвестен -> отказ); done_bytes: уже скачано в этой загрузке.
    Возвращает (ok, reason); reason пуст, если всё в порядке.
    """
    size = int(size or 0)
    done = int(done_bytes or 0)
    if size <= 0:
        return False, "unknown size: отказ от неограниченной загрузки"
    if max_file and size > int(max_file):
        return False, f"file too large: {size} > {int(max_file)}"
    if max_total and done + size > int(max_total):
        return False, f"total limit exceeded: {done + size} > {int(max_total)}"
    return True, ""
