#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Чтение XLSX на stdlib (v3, L3) — без внешних зависимостей.

Поддерживает общий случай: sharedStrings, inline strings, числовые ячейки. Возвращает строки
первого листа (или листа с заданным именем) как список списков строк.
"""
from __future__ import annotations

import io
import re
import zipfile
import xml.etree.ElementTree as ET

NS = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
_CELL_RE = re.compile(r"^([A-Z]+)(\d+)$")


def _col_index(ref: str) -> int:
    m = _CELL_RE.match(ref or "")
    if not m:
        return 0
    letters = m.group(1)
    n = 0
    for ch in letters:
        n = n * 26 + (ord(ch) - 64)
    return n - 1


def _shared_strings(zf: zipfile.ZipFile) -> list[str]:
    try:
        data = zf.read("xl/sharedStrings.xml")
    except KeyError:
        return []
    root = ET.fromstring(data)
    out = []
    for si in root.findall(f"{NS}si"):
        out.append("".join(t.text or "" for t in si.iter(f"{NS}t")))
    return out


def _sheet_path(zf: zipfile.ZipFile, sheet_name: str | None) -> str:
    if not sheet_name:
        names = [n for n in zf.namelist() if n.startswith("xl/worksheets/sheet") and n.endswith(".xml")]
        return sorted(names)[0] if names else "xl/worksheets/sheet1.xml"
    wb = ET.fromstring(zf.read("xl/workbook.xml"))
    rels = ET.fromstring(zf.read("xl/_rels/workbook.xml.rels"))
    rid_to_target = {r.get("Id"): r.get("Target") for r in rels}
    for sh in wb.iter(f"{NS}sheet"):
        if sh.get("name") == sheet_name:
            rid = sh.get("{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id")
            target = rid_to_target.get(rid, "worksheets/sheet1.xml")
            return "xl/" + target.lstrip("/").replace("xl/", "", 1)
    return "xl/worksheets/sheet1.xml"


def read_xlsx_rows(source, sheet_name: str | None = None) -> list[list[str]]:
    """source: путь к файлу или bytes. Возвращает строки первого/заданного листа."""
    if isinstance(source, (bytes, bytearray)):
        zf = zipfile.ZipFile(io.BytesIO(source))
    else:
        zf = zipfile.ZipFile(source)
    with zf:
        shared = _shared_strings(zf)
        root = ET.fromstring(zf.read(_sheet_path(zf, sheet_name)))
        rows: list[list[str]] = []
        for row in root.iter(f"{NS}row"):
            cells: dict[int, str] = {}
            for c in row.findall(f"{NS}c"):
                idx = _col_index(c.get("r", ""))
                t = c.get("t")
                if t == "inlineStr":
                    is_el = c.find(f"{NS}is")
                    val = "".join(x.text or "" for x in is_el.iter(f"{NS}t")) if is_el is not None else ""
                else:
                    v = c.find(f"{NS}v")
                    raw = v.text if v is not None and v.text is not None else ""
                    if t == "s":
                        val = shared[int(raw)] if raw.isdigit() and int(raw) < len(shared) else ""
                    else:
                        val = raw
                cells[idx] = val
            width = (max(cells) + 1) if cells else 0
            rows.append([cells.get(i, "") for i in range(width)])
        return rows
