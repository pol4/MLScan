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


# --- U5: index-адаптеры GGUF и ONNX (range-read) ------------------------------

EXEC_MARKERS = ("curl ", "wget ", "| bash", "| sh", "os.system", "subprocess", "eval(",
                "__import__", "base64 -d", "powershell", "iex(")


def _meta_payload(hits):
    return _f("EXEC-02", "Полезная нагрузка в метаданных", "high", 0.7, "metadata: " + ", ".join(hits[:4]))


def analyze_gguf(reader, total_size: int, **_) -> dict:
    """Индексный разбор GGUF: заголовок + key-value metadata (полностью), без тензорных данных."""
    findings: list[dict] = []
    coverage = {"index": False, "tensors_total": 0, "tensors_sampled": 0, "bytes_read": 0,
                "index_ratio": 0.0, "data_ratio": 0.0}
    details: dict = {}
    # инкрементальное чтение метаданных: начинаем с 1 МиБ и растём до 16 МиБ (тензоры не читаем)
    head = b""
    meta = {}
    try:
        import gguf as _g
    except Exception:  # noqa: BLE001
        _g = None
    for cap in (1 * 1024 ** 2, 4 * 1024 ** 2, 16 * 1024 ** 2):
        head = reader(0, min(total_size, cap))
        coverage["bytes_read"] += len(head)
        if _g is None:
            break
        meta = _g.parse_gguf_meta(head)
        if meta:
            break
        if len(head) < cap:
            break
    if head[:4] != b"GGUF":
        findings.append(_f("FMT-01", "GGUF: неверная сигнатура", "medium", 0.5, head[:4].hex()))
        return {"format": "gguf", "coverage": coverage, "findings": findings, "details": details}
    if meta:
        coverage["index"] = True
        coverage["index_ratio"] = 1.0
        coverage["tensors_total"] = int(meta.get("tensors") or 0)
        md = meta.get("meta") or {}
        details["architecture"] = md.get("general.architecture", "")
        details["gguf_version"] = meta.get("version")
        blob = " ".join(str(v) for v in md.values()).lower()
        hits = [h for h in EXEC_MARKERS if h in blob]
        if hits:
            findings.append(_meta_payload(hits))
    else:
        findings.append(_f("FMT-01", "GGUF: metadata не разобраны", "medium", 0.5, "truncated/invalid"))
    return {"format": "gguf", "coverage": coverage, "findings": findings, "details": details}


def analyze_onnx(reader, total_size: int, *, probe=4 * 1024 * 1024, **_) -> dict:
    """Базовый разбор ONNX (protobuf): заголовок + поиск подозрительных строк; внешние данные."""
    findings: list[dict] = []
    coverage = {"index": False, "tensors_total": 0, "tensors_sampled": 0, "bytes_read": 0,
                "index_ratio": 0.0, "data_ratio": 0.0}
    details: dict = {}
    head = reader(0, min(total_size, probe))
    coverage["bytes_read"] += len(head)
    if not head:
        findings.append(_f("FMT-01", "ONNX: пустой файл", "medium", 0.5, "empty"))
        return {"format": "onnx", "coverage": coverage, "findings": findings, "details": details}
    # protobuf: первые поля — varint ir_version (field 1) / opset; проверяем узнаваемые строки
    low = head.lower()
    if b"onnx" in low or b"pytorch" in low or b"tensorflow" in low or b"ai.onnx" in low:
        coverage["index"] = True
        coverage["index_ratio"] = 1.0
    else:
        findings.append(_f("FMT-01", "ONNX: не найдены ожидаемые идентификаторы модели", "low", 0.4,
                           head[:32].hex()))
    hits = [h for h in EXEC_MARKERS if h.encode() in low]
    if hits:
        findings.append(_meta_payload(hits))
    if b"external_data" in low or b"location" in low:
        findings.append(_f("FMT-12", "ONNX: ссылки на внешние данные (external_data) — проверить целостность",
                           "medium", 0.5, "external_data"))
    details["has_external_data"] = b"external_data" in low
    return {"format": "onnx", "coverage": coverage, "findings": findings, "details": details}


HDF5_SIG = b"\x89HDF\r\n\x1a\n"
PICKLE_STARTS = (b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05")
# Модули, вызовы из которых при десериализации дают исполнение кода/доступ к ФС и сети.
DANGEROUS_GLOBALS = (b"posix", b"nt", b"os", b"subprocess", b"builtins", b"system", b"eval",
                     b"exec", b"pty", b"socket", b"pickle", b"shutil", b"__reduce__")


def analyze_hdf5(reader, total_size: int, *, probe_bytes: int = 4 * 1024 * 1024, **_) -> dict:
    """Статика HDF5 (h5/hdf5/keras): подпись+суперблок и поиск встроенных pickle-потоков.

    HDF5/Keras-файлы часто содержат сериализованные объекты (атрибуты, конфиг Lambda-слоёв) —
    встроенный pickle с опасными GLOBAL даёт исполнение кода при загрузке. Читаем только префикс
    (bounded), полный обход B-деревьев не нужен: сигнатура+поиск pickle дают ранний сигнал.
    """
    findings: list[dict] = []
    details: dict = {}
    probe = min(max(probe_bytes, 4096), total_size) if total_size else probe_bytes
    head = reader(0, min(4096, total_size or 4096)) or b""
    base = 0
    if not head.startswith(HDF5_SIG):                      # суперблок может быть со сдвигом (userblock)
        for off in (512, 1024, 2048, 4096):
            if (total_size or 0) > off + 8:
                chunk = reader(off, 8) or b""
                if chunk.startswith(HDF5_SIG):
                    base = off
                    head = reader(off, min(4096, total_size - off)) or b""
                    break
    coverage = {"index": False, "bytes_read": len(head), "probe_bytes": probe,
                "index_ratio": round(len(head) / max(1, total_size), 4) if total_size else 0.0}
    details["superblock_offset"] = base
    if not head.startswith(HDF5_SIG):
        findings.append(_f("FMT-H5-01", "Сигнатура HDF5 не найдена", "medium", 0.5,
                           "нет \x89HDF\r\n\x1a\n в начале файла/по известным смещениям"))
        return {"format": "hdf5", "coverage": coverage, "findings": findings, "details": details}
    coverage["index"] = True
    sb_ver = head[8] if len(head) > 8 else None
    details["superblock_version"] = sb_ver

    body = reader(base, probe) or b""
    coverage["bytes_read"] = len(body)
    details["probed_bytes"] = len(body)
    hits: list[dict] = []
    dangerous: list[str] = []
    for mark in PICKLE_STARTS:
        pos = body.find(mark)
        while pos != -1 and len(hits) < 16:
            window = body[pos:pos + 4096]
            mods = sorted({m.decode("latin1") for m in DANGEROUS_GLOBALS if m in window})
            if mods:
                dangerous.extend(mods)
            hits.append({"offset": base + pos, "protocol": mark.hex(), "modules": mods})
            pos = body.find(mark, pos + 1)
    details["pickle_streams"] = len(hits)
    if hits:
        uniq = sorted(set(dangerous))
        if uniq:
            findings.append(_f("FMT-H5-02", "Встроенный pickle с опасными GLOBAL в HDF5", "critical", 0.85,
                               f"потоков: {len(hits)}, ссылки: {', '.join(uniq[:6])}"))
        else:
            findings.append(_f("FMT-H5-03", "Встроенный pickle-поток в HDF5", "high", 0.6,
                               f"потоков: {len(hits)} (опасные GLOBAL не найдены)"))
    low = body.lower()
    if b"external" in low and b"_refs" in low:
        findings.append(_f("FMT-H5-04", "Возможные внешние ссылки HDF5", "low", 0.4,
                           "найдены маркеры external/_refs — данные могут лежать вне файла"))
        details["has_external_refs"] = True
    return {"format": "hdf5", "coverage": coverage, "findings": findings, "details": details}


def analyze(reader, total_size: int, fmt: str = "safetensors", **kw) -> dict:
    """Диспетчер index-адаптеров по формату."""
    f = (fmt or "").lower()
    if f == "gguf":
        return analyze_gguf(reader, total_size, **kw)
    if f in ("onnx",):
        return analyze_onnx(reader, total_size, **kw)
    if f in ("hdf5", "h5", "keras"):
        return analyze_hdf5(reader, total_size, **kw)
    return analyze_safetensors(reader, total_size, **kw)
