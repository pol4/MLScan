#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MLScan format adapters (Wave 1): детект формата и статические проверки
на исполнение кода для model-as-code, Keras/SavedModel, ONNX, HDF5, GGUF/шаблонов.

Только stdlib. Возвращает находки в формате, совместимом с `mlscan_poc`:
{check_id, category, title, severity, confidence, evidence}.
"""
from __future__ import annotations

import json
import re
import zipfile
from pathlib import Path

MAGIC_HDF5 = b"\x89HDF\r\n\x1a\n"
ZIP_MAGIC = b"PK\x03\x04"

PY_CODE_HINTS = ("import ", "subprocess", "os.system", "eval(", "exec(", "__import__", "socket")
JINJA_DANGER = ("__class__", "__mro__", "__globals__", "__subclasses__", "cycler", "lipsum",
                "config", "request", "self.", "os.popen", "subprocess")

CODE_EXT = {".py", ".pyw", ".pyc"}
MODEL_CODE_EXT = {".mar", ".mlflow"}


def _f(cid, title, sev, conf, ev, cat="EXEC"):
    return {"check_id": cid, "category": cat, "title": title,
            "severity": sev, "confidence": conf, "evidence": ev}


def _btext(blob: bytes) -> str:
    return blob.decode("utf-8", "replace")


def _scan_python(text: str, label: str) -> list[dict]:
    hits = [h for h in PY_CODE_HINTS if h in text]
    if not hits:
        return []
    return [_f("EXEC-02", f"Python-код в артефакте ({label})", "high", 0.85,
               "hints: " + ", ".join(hits))]


def _scan_json(text: str, label: str) -> list[dict]:
    out: list[dict] = []
    try:
        data = json.loads(text)
    except Exception:  # noqa: BLE001
        return out
    s = json.dumps(data, ensure_ascii=False)
    if '"auto_map"' in s or "trust_remote_code" in s:
        out.append(_f("EXEC-04", f"Ссылка на удалённый код (auto_map/trust_remote_code) в {label}",
                      "critical", 0.85, "auto_map/trust_remote_code"))
    if "Lambda" in s or 'class_name": "Lambda' in s or "custom_objects" in s:
        out.append(_f("EXEC-05", f"Keras Lambda/custom_objects в {label}", "critical", 0.8,
                      "Lambda/custom_objects"))
    if '"chat_template"' in s:
        tpl = ""
        try:
            tpl = str(data.get("chat_template") or "")
        except Exception:  # noqa: BLE001
            tpl = ""
        bad = [d for d in JINJA_DANGER if d in tpl]
        if bad:
            out.append(_f("INJ-01", f"Опасные конструкции в Jinja chat_template ({label})",
                          "high", 0.75, "tokens: " + ", ".join(bad), cat="INJ"))
        elif tpl:
            out.append(_f("INJ-02", f"Найден chat_template ({label}) — требуется проверка",
                          "medium", 0.5, "chat_template присутствует", cat="INJ"))
    return out


def _scan_zip(path: Path) -> tuple[list[dict], str]:
    out: list[dict] = []
    fmt = "zip"
    try:
        zf = zipfile.ZipFile(path)
        names = zf.namelist()
    except Exception as exc:  # noqa: BLE001
        return [_f("FMT-01", "Повреждённый zip-контейнер", "low", 0.4, str(exc), cat="FMT")], fmt
    low = [n.lower() for n in names]
    if any(n.endswith("mar-inf/manifest.json") for n in low):
        fmt = "torchserve-mar"
    has_py = [n for n in names if Path(n).suffix.lower() in CODE_EXT]
    if has_py:
        out.append(_f("EXEC-02", f"Python-код внутри контейнера ({', '.join(has_py[:4])})",
                      "high", 0.85, "files: " + ", ".join(has_py[:6])))
    if fmt == "torchserve-mar" and has_py:
        out.append(_f("EXEC-01", "TorchServe .mar с handler-кодом (исполнение при serve)",
                      "critical", 0.9, "MAR-INF + handler.py"))
    if any(n in ("mar-inf/manifest.json",) for n in low):
        pass
    if any(n.startswith("code/") or n.endswith("constants.pkl") for n in low):
        out.append(_f("EXEC-03", "torch.package/TorchScript с кодом внутри архива",
                      "high", 0.85, "code/ или constants.pkl"))
    # конфиги внутри zip (Keras .keras, прочее)
    for n in names:
        ln = n.lower()
        if ln.endswith((".json", ".yaml", ".yml")):
            try:
                txt = _btext(zf.read(n))
            except Exception:  # noqa: BLE001
                continue
            if ln.endswith(".json"):
                out.extend(_scan_json(txt, f"{path.name}:{n}"))
        if ln.endswith(".py"):
            try:
                out.extend(_scan_python(_btext(zf.read(n)), f"{path.name}:{n}"))
            except Exception:  # noqa: BLE001
                pass
    if path.suffix.lower() == ".keras":
        fmt = "keras"
    return out, fmt


def _scan_hdf5(blob: bytes, label: str) -> list[dict]:
    out: list[dict] = []
    text = _btext(blob)
    if "Lambda" in text or "__reduce__" in text or "external" in text.lower():
        out.append(_f("EXEC-05", f"HDF5: признаки Lambda/__reduce__/external ({label})",
                      "high", 0.7, "strings found"))
    if "external link" in text.lower() or "external_link" in text.lower():
        out.append(_f("EXEC-07", f"HDF5: внешние ссылки ({label})", "high", 0.7, "external link"))
    return out


def _scan_onnx(blob: bytes, label: str) -> list[dict]:
    out: list[dict] = []
    if b"external_data" in blob or b"external_data_helper" in blob:
        out.append(_f("EXEC-06", f"ONNX external_data ({label}) — риск path traversal/URL",
                      "high", 0.8, "external_data"))
    if b"custom" in blob or b"ai.onnx.contrib" in blob or b"com.microsoft" in blob:
        out.append(_f("EXEC-06", f"ONNX custom/contrib ops ({label})", "high", 0.7,
                      "custom ops/domain"))
    if b"location" in blob:
        out.append(_f("FMT-09", f"ONNX external location ({label})", "medium", 0.6, "location"))
    return out


def _scan_gguf(blob: bytes, label: str) -> list[dict]:
    out: list[dict] = []
    if b"chat_template" in blob:
        text = _btext(blob)
        bad = [d for d in JINJA_DANGER if d in text]
        if bad:
            out.append(_f("INJ-01", f"GGUF chat_template с опасными конструкциями ({label})",
                          "high", 0.7, "tokens: " + ", ".join(bad), cat="INJ"))
        else:
            out.append(_f("INJ-02", f"GGUF chat_template присутствует ({label})", "medium", 0.5,
                          "chat_template", cat="INJ"))
    return out


def detect(path: Path, head: bytes) -> str:
    ext = path.suffix.lower()
    if head.startswith(ZIP_MAGIC):
        try:
            names = [n.lower() for n in zipfile.ZipFile(path).namelist()]
        except Exception:  # noqa: BLE001
            names = []
        if any(n.endswith("mar-inf/manifest.json") for n in names):
            return "torchserve-mar"
        if ext == ".keras" or any(n.endswith("config.json") for n in names):
            return "keras"
        if any(n.startswith("code/") for n in names):
            return "torch-package"
        if any(n == "data.pkl" for n in names):
            return "torch-zip"
        return "zip"
    if head.startswith(MAGIC_HDF5):
        return "hdf5"
    if ext in CODE_EXT:
        return "python"
    if ext in MODEL_CODE_EXT:
        return "model-as-code"
    if ext == ".onnx":
        return "onnx"
    if ext == ".gguf":
        return "gguf"
    if ext in (".json", ".yaml", ".yml"):
        return "config"
    if head[:2] in (b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05"):
        return "pickle"
    return "unknown"


def static_scan(path: Path) -> dict:
    """Адаптер: вернуть {format, findings, details} для не-pickle форматов."""
    try:
        with path.open("rb") as fh:
            head = fh.read(4096)
    except Exception as exc:  # noqa: BLE001
        return {"format": "unknown", "findings": [], "error": str(exc)}
    fmt = detect(path, head)
    findings: list[dict] = []
    try:
        if fmt in ("torchserve-mar", "keras", "torch-package", "torch-zip", "zip"):
            f2, real = _scan_zip(path)
            findings.extend(f2)
            fmt = real if real != "zip" else fmt
        elif fmt == "python":
            findings.extend(_scan_python(_btext(path.read_bytes()), path.name))
        elif fmt == "model-as-code":
            text = _btext(path.read_bytes())
            findings.append(_f("EXEC-01", f"Model-as-code артефакт ({path.name})", "high", 0.9,
                               "исполняемый артефакт"))
            findings.extend(_scan_python(text, path.name))
        elif fmt == "onnx":
            findings.extend(_scan_onnx(path.read_bytes(), path.name))
        elif fmt == "hdf5":
            findings.extend(_scan_hdf5(path.read_bytes(), path.name))
        elif fmt == "gguf":
            findings.extend(_scan_gguf(path.read_bytes(), path.name))
        elif fmt == "config":
            findings.extend(_scan_json(_btext(path.read_bytes()), path.name))
    except Exception as exc:  # noqa: BLE001
        findings.append(_f("FMT-01", f"Ошибка разбора {fmt}", "low", 0.3, str(exc), cat="FMT"))
    # проверка несоответствия расширения реальному формату
    ext = path.suffix.lower()
    if fmt in ("python", "torchserve-mar") and ext not in (".py", ".mar"):
        findings.append(_f("FMT-02", f"Несоответствие расширения и формата: {ext} -> {fmt}",
                           "medium", 0.7, f"ext={ext} real={fmt}", cat="FMT"))
    return {"format": fmt, "findings": findings}
