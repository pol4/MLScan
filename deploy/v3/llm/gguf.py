#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Минимальный парсер метаданных GGUF (v3, L0/U2) на stdlib — для авто-классификации LLM.

Читает заголовок и key-value метаданные из префикса файла (range-read), извлекает
`general.architecture` и др., достаточные для определения LLM и семьи без ручной подсказки.
"""
from __future__ import annotations

import struct

MAGIC = b"GGUF"
# типы значений GGUF
T_UINT8, T_INT8, T_UINT16, T_INT16, T_UINT32, T_INT32, T_FLOAT32, T_BOOL, T_STRING, T_ARRAY, \
    T_UINT64, T_INT64, T_FLOAT64 = range(13)

_SCALAR = {
    T_UINT8: ("<B", 1), T_INT8: ("<b", 1), T_UINT16: ("<H", 2), T_INT16: ("<h", 2),
    T_UINT32: ("<I", 4), T_INT32: ("<i", 4), T_FLOAT32: ("<f", 4), T_BOOL: ("<B", 1),
    T_UINT64: ("<Q", 8), T_INT64: ("<q", 8), T_FLOAT64: ("<d", 8),
}


class _Buf:
    def __init__(self, data: bytes):
        self.d = data
        self.i = 0

    def take(self, n: int) -> bytes:
        if self.i + n > len(self.d):
            raise EOFError("truncated gguf")
        b = self.d[self.i:self.i + n]
        self.i += n
        return b

    def u32(self) -> int:
        return struct.unpack("<I", self.take(4))[0]

    def u64(self) -> int:
        return struct.unpack("<Q", self.take(8))[0]


def _read_string(b: _Buf) -> str:
    n = b.u64()
    if n > 1 << 20:
        raise ValueError("gguf string too long")
    return b.take(n).decode("utf-8", "replace")


def _read_value(b: _Buf, t: int):
    if t in _SCALAR:
        fmt, sz = _SCALAR[t]
        return struct.unpack(fmt, b.take(sz))[0]
    if t == T_STRING:
        return _read_string(b)
    if t == T_ARRAY:
        et = b.u32()
        cnt = b.u64()
        return [_read_value(b, et) for _ in range(min(cnt, 64))]  # ограничиваем объём
    return None


def parse_gguf_meta(head: bytes, *, max_kv: int = 256) -> dict:
    """Возвращает {'version':int,'tensors':int,'meta':{key:value}} из префикса файла."""
    if not head or head[:4] != MAGIC:
        return {}
    try:
        b = _Buf(head)
        b.i = 4
        version = b.u32()
        n_tensors = b.u64()
        n_kv = b.u64()
        meta: dict = {}
        for _ in range(min(int(n_kv), max_kv)):
            key = _read_string(b)
            t = b.u32()
            meta[key] = _read_value(b, t)
        return {"version": version, "tensors": int(n_tensors), "meta": meta}
    except (EOFError, ValueError, struct.error):
        return {}


def architecture(head: bytes) -> str:
    m = parse_gguf_meta(head)
    return str((m.get("meta") or {}).get("general.architecture", "")).lower()
