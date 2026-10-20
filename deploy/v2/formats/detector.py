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


def _scan_safetensors(blob: bytes, label: str) -> list[dict]:
    import struct
    out: list[dict] = []
    if len(blob) < 8:
        return [_f("FMT-01", f"SafeTensors: файл слишком мал ({label})", "medium", 0.5, "len<8", cat="FMT")]
    (hlen,) = struct.unpack("<Q", blob[:8])
    if hlen <= 0 or hlen > len(blob) - 8:
        return [_f("FMT-01", f"SafeTensors: некорректная длина заголовка ({label})",
                   "high", 0.8, f"header_len={hlen}", cat="FMT")]
    try:
        header = json.loads(blob[8:8 + hlen].decode("utf-8", "replace"))
    except Exception as exc:  # noqa: BLE001
        return [_f("FMT-01", f"SafeTensors: нечитаемый заголовок ({label})", "high", 0.8, str(exc), cat="FMT")]
    data_start = 8 + hlen
    data_len = len(blob) - data_start
    ranges = []
    for name, info in header.items():
        if name == "__metadata__":
            continue
        try:
            beg, end = info.get("data_offsets", (0, 0))
        except Exception:  # noqa: BLE001
            continue
        if beg < 0 or end > data_len or end < beg:
            out.append(_f("FMT-02", f"SafeTensors: выход за границы тензора {name} ({label})",
                          "high", 0.8, f"offsets={beg},{end} data_len={data_len}", cat="FMT"))
        ranges.append((beg, end))
    ranges.sort()
    for i in range(1, len(ranges)):
        if ranges[i][0] < ranges[i - 1][1]:
            out.append(_f("FMT-02", f"SafeTensors: перекрытие тензоров ({label})", "high", 0.8,
                          f"overlap {ranges[i - 1]} и {ranges[i]}", cat="FMT"))
    if ranges:
        used_end = max(r[1] for r in ranges)
        if used_end < data_len:
            out.append(_f("FMT-11", f"SafeTensors: trailing-данные после тензоров ({label})",
                          "medium", 0.6, f"{data_len - used_end} лишних байт", cat="FMT"))
    # эвристика по весам (BD-01): NaN/Inf и экстремальные значения
    import math
    for name, info in header.items():
        if name == "__metadata__":
            continue
        dtype = str(info.get("dtype", ""))
        if dtype not in ("F32", "F64", "F16"):
            continue
        try:
            beg, end = info["data_offsets"]
        except Exception:  # noqa: BLE001
            continue
        raw = blob[data_start + beg:data_start + end]
        fmtc = {"F32": "f", "F64": "d", "F16": "e"}[dtype]
        sz = {"F32": 4, "F64": 8, "F16": 2}[dtype]
        n = len(raw) // sz
        vals = []
        try:
            for i in range(min(n, 200000)):
                vals.append(struct.unpack_from("<" + fmtc, raw, i * sz)[0])
        except Exception:  # noqa: BLE001
            continue
        if not vals:
            continue
        nan = sum(1 for v in vals if math.isnan(v))
        inf = sum(1 for v in vals if math.isinf(v))
        absmax = max(abs(v) for v in vals if not math.isnan(v) and not math.isinf(v)) if (nan + inf < len(vals)) else 0.0
        if nan or inf:
            out.append(_f("BD-01", f"Веса: NaN/Inf в тензоре {name} ({label})", "high", 0.7,
                          f"nan={nan} inf={inf}", cat="BD"))
        elif absmax > 1e6:
            out.append(_f("BD-01", f"Веса: экстремальные значения в тензоре {name} ({label})",
                          "medium", 0.5, f"absmax={absmax:.1f}", cat="BD"))
    return out


def _scan_zip_extra(path: Path) -> list[dict]:
    out: list[dict] = []
    try:
        zf = zipfile.ZipFile(path)
    except Exception:  # noqa: BLE001
        return out
    total_c = total_u = 0
    for i in zf.infolist():
        total_c += i.compress_size
        total_u += i.file_size
        n = i.filename
        if n.startswith("/") or ".." in Path(n).parts:
            out.append(_f("FMT-03", f"Zip: подозрительный путь ({n})", "high", 0.8,
                          "path traversal/absolute", cat="FMT"))
    if total_c > 0 and total_u / max(1, total_c) > 100 and total_u > 10 * 1024 * 1024:
        out.append(_f("FMT-04", "Zip: высокая степень сжатия (bomb)", "high", 0.7,
                      f"ratio={total_u / max(1, total_c):.0f}", cat="FMT"))
    return out


def _scan_tar(path: Path) -> list[dict]:
    import tarfile
    out: list[dict] = []
    try:
        tf = tarfile.open(path)
    except Exception:  # noqa: BLE001
        return [_f("FMT-01", "Повреждённый tar-архив", "low", 0.3, str(path.name), cat="FMT")]
    total_u = 0
    for m in tf.getmembers():
        if m.name.startswith("/") or ".." in Path(m.name).parts:
            out.append(_f("FMT-03", f"Tar: подозрительный путь ({m.name})", "high", 0.8,
                          "path traversal/absolute", cat="FMT"))
        if m.issym() or m.islnk():
            out.append(_f("FMT-05", f"Tar: ссылка/жёсткая ссылка ({m.name})", "high", 0.7,
                          "symlink/hardlink", cat="FMT"))
        total_u += m.size
    if total_u > 10 * 1024 * 1024 * 1024:
        out.append(_f("FMT-04", "Tar: чрезмерный суммарный размер (bomb)", "medium", 0.5,
                      f"size={total_u}", cat="FMT"))
    return out


def _scan_xml(blob: bytes, label: str) -> list[dict]:
    if b"<!DOCTYPE" in blob or b"<!ENTITY" in blob:
        return [_f("FMT-06", f"XML: DOCTYPE/ENTITY (XXE) в {label}", "high", 0.75,
                   "doctype/entity", cat="FMT")]
    return []


def _scan_yaml(text: str, label: str) -> list[dict]:
    bad = [t for t in ("!!python/object", "!!python/name", "!!python/apply", "!!python/module")
           if t in text]
    if bad:
        return [_f("FMT-06", f"YAML: unsafe-тег ({', '.join(bad)}) в {label}", "high", 0.8,
                   "unsafe yaml tags", cat="FMT")]
    return []


def _scan_tokenizer(data: dict, label: str) -> list[dict]:
    out: list[dict] = []
    specials = {"<|endoftext|>", "<s>", "</s>", "<pad>", "<unk>", "[CLS]", "[SEP]"}
    added = data.get("added_tokens") or []
    override = [t for t in added if isinstance(t, dict) and t.get("special")
                and str(t.get("content")) in specials and t.get("normalized")]
    if override:
        out.append(_f("BD-02", f"Токенизатор: переопределение спец-токенов ({label})", "high", 0.75,
                      str([t.get("content") for t in override][:5]), cat="BD"))
    blob = json.dumps(data, ensure_ascii=False)
    if '"Regex"' in blob or "regex" in blob:
        import re as _re
        for m in _re.findall(r'"Regex"\s*:\s*"([^"]+)"', blob):
            if _re.search(r"(\([^)]*[+*][^)]*\)[+*])|(\[[^\]]*\][+*]){2,}", m):
                out.append(_f("BD-02", f"Токенизатор: потенциальный ReDoS-regex ({label})", "medium", 0.6,
                              m[:120], cat="BD"))
                break
    return out


CARD_INJECTION = ("ignore previous", "ignore all previous", "system prompt", "you must",
                  "do not tell", "exfiltrate", "send the", "reveal", "jailbreak", "tool call")
CARD_NET = ("http://", "https://", "curl ", "wget ")


def _scan_card(text: str, label: str) -> list[dict]:
    out: list[dict] = []
    low = text.lower()
    hits = [p for p in CARD_INJECTION if p in low]
    if hits:
        out.append(_f("INJ-03", f"Prompt-injection в карточке/документе ({label})", "high", 0.65,
                      "phrases: " + ", ".join(hits[:5]), cat="INJ"))
    if "<!--" in text and any(p in text.lower() for p in ("ignore", "system", "execute")):
        out.append(_f("INJ-03", f"Скрытые HTML-комментарии с инструкциями ({label})", "medium", 0.55,
                      "hidden comment", cat="INJ"))
    if "<script" in low or "javascript:" in low:
        out.append(_f("INJ-05", f"HTML/JS в документе ({label}) — XSS при рендере", "medium", 0.6,
                      "script/javascript", cat="INJ"))
    if any(p in low for p in CARD_NET):
        out.append(_f("INJ-03", f"Сетевые ссылки в карточке ({label})", "low", 0.4,
                      "url/curl/wget", cat="INJ"))
    return out


def _scan_tools(data: dict, label: str) -> list[dict]:
    out: list[dict] = []
    blob = json.dumps(data, ensure_ascii=False).lower()
    if "mcpservers" in blob or ('"command"' in blob and '"args"' in blob):
        out.append(_f("AGT-01", f"MCP/agent-манифест с запуском команд ({label})", "critical", 0.8,
                      "mcpServers/command", cat="AGT"))
    if '"tools"' in blob:
        bad = [p for p in ("ignore", "execute", "read file", "/etc/", "send ", "exfiltrate")
               if p in blob]
        if bad:
            out.append(_f("INJ-04", f"Tool-схема с подозрительными описаниями ({label})", "high", 0.6,
                          "terms: " + ", ".join(bad), cat="INJ"))
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
    if ext == ".safetensors":
        return "safetensors"
    if ext in (".tar", ".tgz", ".gz"):
        return "tar"
    if ext in (".xml", ".pmml", ".ovpn"):
        return "xml"
    if ext in (".json", ".yaml", ".yml"):
        return "config"
    if ext in (".md", ".txt", ".rst"):
        return "card"
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
            findings.extend(_scan_zip_extra(path))
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
        elif fmt == "safetensors":
            findings.extend(_scan_safetensors(path.read_bytes(), path.name))
        elif fmt == "tar":
            findings.extend(_scan_tar(path))
        elif fmt == "xml":
            findings.extend(_scan_xml(path.read_bytes(), path.name))
        elif fmt == "config":
            blob = path.read_bytes()
            text = _btext(blob)
            findings.extend(_scan_json(text, path.name))
            if path.suffix.lower() in (".yaml", ".yml"):
                findings.extend(_scan_yaml(text, path.name))
            if path.suffix.lower() == ".json":
                try:
                    data = json.loads(text)
                except Exception:  # noqa: BLE001
                    data = None
                if isinstance(data, dict):
                    if any(k in data for k in ("added_tokens", "normalizer", "pre_tokenizer", "model")):
                        findings.extend(_scan_tokenizer(data, path.name))
                    findings.extend(_scan_tools(data, path.name))
        elif fmt == "card":
            findings.extend(_scan_card(_btext(path.read_bytes()), path.name))
    except Exception as exc:  # noqa: BLE001
        findings.append(_f("FMT-01", f"Ошибка разбора {fmt}", "low", 0.3, str(exc), cat="FMT"))
    # проверка несоответствия расширения реальному формату
    ext = path.suffix.lower()
    if fmt in ("python", "torchserve-mar") and ext not in (".py", ".mar"):
        findings.append(_f("FMT-02", f"Несоответствие расширения и формата: {ext} -> {fmt}",
                           "medium", 0.7, f"ext={ext} real={fmt}", cat="FMT"))
    return {"format": fmt, "findings": findings}
