#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Потоковый статический анализ v3 (P3): index-driven обход через range-read.

Анализ не читает объект целиком: работает с абстракцией `reader(offset, length) -> bytes`
(в проде — S3 range-read). Для safetensors: полный обход заголовка/индекса (100 %) + выборочное
чтение диапазонов тензоров (sampling) для эвристик (NaN/Inf/экстремумы). Возвращает findings и
явное **coverage** (что прочитано/проверено).
"""
from __future__ import annotations

import json
import math
import struct

MAX_HEADER = 64 * 1024 * 1024      # защита от «гигантского» заголовка
EXTREME = 1e6


def _f(check_id, title, severity, confidence, evidence):
    return {"check_id": check_id, "category": "FMT", "title": title, "severity": severity,
            "confidence": confidence, "evidence": evidence}


def analyze_safetensors(reader, total_size: int, *, sample_per_tensor: int = 3,
                        sample_bytes: int = 4096) -> dict:
    """reader(offset, length) -> bytes. Возвращает {format,coverage,findings,details}."""
    findings: list[dict] = []
    coverage = {"index": False, "tensors_total": 0, "tensors_sampled": 0,
                "bytes_read": 0, "index_ratio": 0.0, "data_ratio": 0.0}
    details: dict = {}

    head = reader(0, 8)
    coverage["bytes_read"] += len(head)
    if len(head) < 8:
        findings.append(_f("FMT-01", "SafeTensors: файл слишком мал", "medium", 0.5, "len<8"))
        return {"format": "safetensors", "coverage": coverage, "findings": findings, "details": details}
    (hlen,) = struct.unpack("<Q", head)
    if hlen <= 0 or hlen > MAX_HEADER or hlen + 8 > total_size:
        findings.append(_f("FMT-01", "SafeTensors: некорректная длина заголовка", "high", 0.8,
                           f"header_len={hlen}"))
        return {"format": "safetensors", "coverage": coverage, "findings": findings, "details": details}

    blob = reader(8, hlen)
    coverage["bytes_read"] += len(blob)
    try:
        header = json.loads(blob.decode("utf-8", "replace"))
    except Exception as exc:  # noqa: BLE001
        findings.append(_f("FMT-01", "SafeTensors: нечитаемый заголовок", "high", 0.8, str(exc)))
        return {"format": "safetensors", "coverage": coverage, "findings": findings, "details": details}
    coverage["index"] = True
    coverage["index_ratio"] = 1.0

    meta = header.get("__metadata__") or {}
    if isinstance(meta, dict):
        meta_blob = " ".join(str(v) for v in meta.values()).lower()
        hits = [h for h in ("curl ", "wget ", "| bash", "| sh", "os.system", "subprocess",
                            "eval(", "__import__", "base64 -d", "powershell", "iex(") if h in meta_blob]
        if hits:
            findings.append(_f("EXEC-02", "SafeTensors: полезная нагрузка в метаданных", "high", 0.7,
                               "metadata: " + ", ".join(hits[:4])))

    data_start = 8 + hlen
    data_len = max(total_size - data_start, 0)
    tensors = [(n, i) for n, i in header.items() if n != "__metadata__"]
    coverage["tensors_total"] = len(tensors)
    ranges = []
    fp_tensors = 0
    for name, info in tensors:
        try:
            beg, end = info.get("data_offsets", (0, 0))
        except Exception:  # noqa: BLE001
            continue
        if beg < 0 or end > data_len or end < beg:
            findings.append(_f("FMT-02", f"SafeTensors: выход за границы тензора {name}", "high", 0.8,
                               f"offsets={beg},{end} data_len={data_len}"))
            continue
        ranges.append((beg, end))
        dtype = str(info.get("dtype", ""))
        if dtype in ("F32", "F64", "F16"):
            fp_tensors += 1
            if _sample_tensor(reader, data_start, beg, end, dtype, sample_per_tensor, sample_bytes,
                              coverage):
                findings.append(_f("BD-01", f"SafeTensors: аномальные значения в тензоре {name}",
                                   "high", 0.6, "nan/inf/extreme в сэмпле"))
            coverage["tensors_sampled"] += 1
    ranges.sort()
    for i in range(1, len(ranges)):
        if ranges[i][0] < ranges[i - 1][1]:
            findings.append(_f("FMT-02", "SafeTensors: перекрытие тензоров", "high", 0.8,
                               f"overlap {ranges[i-1]} и {ranges[i]}"))
    if ranges:
        used_end = max(r[1] for r in ranges)
        if used_end < data_len:
            findings.append(_f("FMT-11", "SafeTensors: trailing-данные после тензоров", "medium", 0.6,
                               f"{data_len - used_end} лишних байт"))
    denominator = max(coverage["tensors_total"], 1)
    coverage["data_ratio"] = round(coverage["tensors_sampled"] / denominator, 4)
    details["fp_tensors"] = fp_tensors
    details["payload_in_metadata"] = bool(meta)
    return {"format": "safetensors", "coverage": coverage, "findings": findings, "details": details}


def _sample_tensor(reader, data_start, beg, end, dtype, n_samples, sample_bytes, coverage) -> bool:
    fmtc = {"F32": "f", "F64": "d", "F16": "e"}[dtype]
    sz = {"F32": 4, "F64": 8, "F16": 2}[dtype]
    n_elems = max((end - beg) // sz, 1)
    spots = sorted({0, n_elems // 2, n_elems - 1} if n_samples >= 3 else {0})
    anom = False
    per = max(sample_bytes // sz, 1)
    for e0 in spots:
        off = data_start + beg + e0 * sz
        take = min(per, max(n_elems - e0, 1))
        raw = reader(off, take * sz)
        coverage["bytes_read"] += len(raw)
        cnt = len(raw) // sz
        if cnt == 0:
            continue
        vals = struct.unpack("<" + fmtc * cnt, raw[:cnt * sz])
        for v in vals:
            if math.isnan(v) or math.isinf(v) or abs(v) > EXTREME:
                anom = True
                break
        if anom:
            break
    return anom
