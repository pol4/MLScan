#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Членный обход архивов v3 (P4) через range-read.

Чтение оглавления без скачивания данных: zip — центральный каталог из «хвоста» (range), tar —
последовательные 512-байтные заголовки. Бюджеты (число членов, размеры, суммарный объём, глубина),
защита от zip-slip (абсолютные пути/«..») и bomb (аномальный коэффициент сжатия). Каждый член —
диапазон (offset,len), анализ читает только его.
"""
from __future__ import annotations

import io
import struct
import zlib

ZIP_EOCD = b"PK\x05\x06"
ZIP_EOCD64 = b"PK\x06\x06"
ZIP_EOCD64_LOC = b"PK\x06\x07"
ZIP_CD = b"PK\x01\x02"
DEFAULT_BUDGET = {"max_members": 100000, "max_member_bytes": 8 * 1024 ** 3,
                  "total_budget_bytes": 64 * 1024 ** 3, "depth": 4, "bomb_ratio": 100.0,
                  "max_inflate_bytes": 256 * 1024 ** 2}


def _finding(check_id, title, severity, conf, evidence):
    return {"check_id": check_id, "category": "FMT", "title": title, "severity": severity,
            "confidence": conf, "evidence": evidence}


def _unsafe_name(name: str) -> bool:
    n = (name or "").replace("\\", "/")
    return n.startswith("/") or "./.." in ("/" + n) or n.startswith("../") or "/../" in n or n == ".."


def list_members_zip(reader, total_size: int, *, budgets=None) -> dict:
    b = {**DEFAULT_BUDGET, **(budgets or {})}
    findings: list[dict] = []
    tail_len = min(total_size, 65557 + 22)
    tail = reader(total_size - tail_len, tail_len)
    pos = tail.rfind(ZIP_EOCD)
    if pos < 0:
        return {"ok": False, "members": [], "findings": [_finding("FMT-01", "Архив: EOCD не найден",
                "medium", 0.5, "zip")], "bytes_read": len(tail)}
    eocd = tail[pos:pos + 22]
    cd_size, cd_off = struct.unpack("<II", eocd[12:20])
    bytes_read = len(tail)
    if cd_off == 0xFFFFFFFF or cd_size == 0xFFFFFFFF:
        loc = tail.rfind(ZIP_EOCD64_LOC)
        if loc >= 0:
            z64_off = struct.unpack("<Q", tail[loc + 8:loc + 16])[0]
            z64 = reader(z64_off, 56)
            bytes_read += len(z64)
            if z64[:4] == ZIP_EOCD64:
                cd_size = struct.unpack("<Q", z64[40:48])[0]
                cd_off = struct.unpack("<Q", z64[48:56])[0]
    if cd_off + cd_size > total_size or cd_size == 0:
        return {"ok": False, "members": [], "findings": [_finding("FMT-01", "Архив: некорректный "
                "центральный каталог", "high", 0.7, f"off={cd_off} size={cd_size}")],
                "bytes_read": bytes_read}
    cd = reader(cd_off, cd_size)
    bytes_read += len(cd)
    members = _parse_central_directory(cd, cd_off)
    members, fs = _apply_budgets(members, b)
    findings.extend(fs)
    return {"ok": True, "members": members, "findings": findings, "bytes_read": bytes_read,
            "index_ratio": 1.0}


def _parse_central_directory(cd: bytes, cd_off: int) -> list[dict]:
    out: list[dict] = []
    i = 0
    while i + 46 <= len(cd) and cd[i:i + 4] == ZIP_CD:
        (name_len, extra_len, comment_len) = struct.unpack("<HHH", cd[i + 28:i + 34])
        comp, uncomp = struct.unpack("<II", cd[i + 20:i + 28])
        lho = struct.unpack("<I", cd[i + 42:i + 46])[0]
        name = cd[i + 46:i + 46 + name_len].decode("utf-8", "replace")
        out.append({"name": name, "header_off": lho, "compressed": comp, "uncompressed": uncomp,
                    "cd_off": cd_off + i})
        i += 46 + name_len + extra_len + comment_len
    return out


def list_members_tar(reader, total_size: int, *, budgets=None) -> dict:
    b = {**DEFAULT_BUDGET, **(budgets or {})}
    findings: list[dict] = []
    members: list[dict] = []
    off = 0
    bytes_read = 0
    zeros = 0
    while off + 512 <= total_size and len(members) < int(b["max_members"]):
        blk = reader(off, 512)
        bytes_read += len(blk)
        if len(blk) < 512:
            break
        if blk == b"\x00" * 512:
            zeros += 1
            off += 512
            if zeros >= 2:
                break
            continue
        zeros = 0
        name = blk[0:100].split(b"\x00", 1)[0].decode("utf-8", "replace")
        size = int(blk[124:136].split(b"\x00", 1)[0].strip() or b"0", 8)
        data_off = off + 512
        members.append({"name": name, "header_off": off, "data_off": data_off,
                        "compressed": size, "uncompressed": size})
        off = data_off + ((size + 511) // 512) * 512
    members, fs = _apply_budgets(members, b)
    findings.extend(fs)
    return {"ok": True, "members": members, "findings": findings, "bytes_read": bytes_read,
            "index_ratio": 1.0}


def _apply_budgets(members: list[dict], b: dict) -> tuple[list[dict], list[dict]]:
    findings: list[dict] = []
    out: list[dict] = []
    total = 0
    for m in members:
        if _unsafe_name(m["name"]):
            m["skip_reason"] = "zip-slip"
            findings.append(_finding("ARCH-SLIP", f"Архив: небезопасный путь члена {m['name']}",
                                     "high", 0.85, m["name"]))
            out.append(m)
            continue
        comp = max(int(m.get("compressed") or 0), 0)
        uncomp = max(int(m.get("uncompressed") or 0), 0)
        if comp > 0 and uncomp / comp >= float(b["bomb_ratio"]):
            m["skip_reason"] = "bomb"
            findings.append(_finding("ARCH-BOMB", f"Архив: аномальное сжатие члена {m['name']}",
                                     "high", 0.7, f"ratio={uncomp / comp:.0f}"))
            out.append(m)
            continue
        if uncomp > int(b["max_member_bytes"]):
            m["skip_reason"] = "member_bytes"
            out.append(m)
            continue
        if total + uncomp > int(b["total_budget_bytes"]):
            m["skip_reason"] = "total_budget"
            out.append(m)
            continue
        total += uncomp
        out.append(m)
    if len(out) > int(b["max_members"]):
        for m in out[int(b["max_members"]):]:
            m.setdefault("skip_reason", "max_members")
    return out, findings


def plan_members(members: list[dict], *, budgets=None) -> dict:
    b = {**DEFAULT_BUDGET, **(budgets or {})}
    analyzable = [m for m in members if not m.get("skip_reason")]
    return {"total": len(members), "analyzable": len(analyzable),
            "skipped": len(members) - len(analyzable),
            "budget": b, "plan": [m["name"] for m in analyzable]}


def _looks_like_archive(name: str, data: bytes) -> str:
    n = (name or "").lower()
    if data[:4] == ZIP_CD or data[:2] == b"PK":
        return "zip"
    if data[:2] == b"\x1f\x8b":
        return "gzip"
    if len(data) > 262 and data[257:262] == b"ustar":
        return "tar"
    if n.endswith((".zip", ".tar", ".tgz", ".tar.gz", ".gz")):
        return "byext"
    return ""


def member_bytes(reader, member: dict, *, decompress: bool = True, max_inflate: int = 256 * 1024 ** 2) -> bytes:
    """Прочитать данные члена zip по диапазону (local header -> data) и (опц.) распаковать (raw deflate)."""
    lh = reader(member["header_off"], 30)
    if len(lh) < 30:
        return b""
    nlen, elen = struct.unpack("<HH", lh[26:30])
    data_off = member["header_off"] + 30 + nlen + elen
    comp = int(member.get("compressed") or 0)
    raw = reader(data_off, comp) if comp else b""
    if not decompress:
        return raw
    if raw[:2] == b"PK" or raw.startswith(b"\x1f\x8b"):
        return raw
    try:
        out = zlib.decompress(raw, -15)
        return out if len(out) <= max_inflate else raw
    except Exception:  # noqa: BLE001
        return raw


def walk_archive(reader, total_size: int, *, depth: int = 4, budgets=None,
                 kind: str = "auto", _level: int = 0) -> dict:
    """Рекурсивный обход архива по range-read: члены + вложенные контейнеры до depth-бюджета."""
    b = {**DEFAULT_BUDGET, **(budgets or {})}
    b["depth"] = int(depth)          # аргумент depth имеет приоритет над budgets
    k = kind
    if k == "auto":
        head = reader(0, 8)
        k = "zip" if head[:2] == b"PK" else ("tar" if head[257:262] == b"ustar" else "zip")
    res = list_members_zip(reader, total_size, budgets=b) if k == "zip" else list_members_tar(reader, total_size, budgets=b)
    tree = {"kind": k, "members": res.get("members", []), "findings": list(res.get("findings", [])),
            "children": [], "level": _level}
    if _level >= int(b["depth"]):
        tree["truncated_depth"] = True
        return tree
    for m in res.get("members", []):
        # zip-slip и превышения бюджетов — не раскрываем; "bomb" допускается к разбору в пределах
        # inflate-бюджета (bounded inflate безопасен), finding при этом сохраняется
        if k != "zip" or m.get("skip_reason") in ("zip-slip", "member_bytes", "total_budget", "max_members"):
            continue
        try:
            data = member_bytes(reader, m, decompress=True, max_inflate=int(b["max_inflate_bytes"]))
        except Exception:  # noqa: BLE001
            continue
        ik = _looks_like_archive(m.get("name", ""), data)
        if not ik or ik in ("gzip", "byext"):
            continue
        buf = io.BytesIO(data)
        child = walk_archive(lambda o, l: buf.getvalue()[o:o + l], len(data), depth=depth,
                             budgets=b, kind="zip" if ik == "zip" else "tar", _level=_level + 1)
        child["name"] = m.get("name")
        tree["children"].append(child)
    return tree


def walk_stats(tree: dict) -> dict:
    """Сводка обхода: число членов/детей по уровням и срабатывания depth-бюджета."""
    members = len(tree.get("members") or [])
    children = tree.get("children") or []
    total_children = sum(1 + (walk_stats(c)["children_total"] if c.get("children") else 0)
                         for c in children)
    return {"members": members, "children": len(children), "children_total": total_children,
            "depth_truncated": any(c.get("truncated_depth") for c in children) or bool(tree.get("truncated_depth")),
            "max_level": max([c.get("level", 0) for c in children] + [tree.get("level", 0)])}
