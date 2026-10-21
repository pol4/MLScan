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

PY_CODE_HINTS = ("subprocess", "os.system", "os.popen", "pty.spawn", "eval(", "exec(",
                 "__import__", "socket.", "urlopen", "requests.get", "marshal.loads",
                 "pickle.loads", "base64 -d", "commands.getoutput")
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


# --- Волна 4: ноутбуки, скрипты, MLflow/SavedModel/TFLite/CoreML/PMML, датасеты ---
NOTEBOOK_EXT = {".ipynb"}
SCRIPT_EXT = {".sh", ".bash", ".zsh", ".ksh", ".ps1", ".bat", ".cmd"}
DATASET_EXT = {".parquet", ".arrow", ".feather", ".ipc"}
PIPE_TO_SHELL = re.compile(r"(curl|wget|iwr|invoke-webrequest)[^\n|]{0,300}\|\s*(ba|z|k)?sh\b", re.I)
SCRIPT_EXEC = ("invoke-expression", "iex(", "downloadstring", "-encodedcommand",
               "frombase64string", "nc -e", "/dev/tcp/", "bash -i", "certutil -urlcache",
               "bitsadmin", "chmod +x", "base64 -d", "python -c", "os.system", "subprocess",
               "eval ", "exec ", "rm -rf /")
NOTEBOOK_SHELL = ("!pip", "!curl", "!wget", "!bash", "!sh ")


def _scan_native(blob: bytes, label: str) -> list[dict]:
    """Нативные библиотеки в пакете модели (.so/.dll/.dylib) — код вне модели."""
    for magic, kind in NATIVE_MAGIC.items():
        if blob.startswith(magic):
            return [_f("EXEC-08", f"Нативная библиотека в артефакте ({label})", "critical", 0.85,
                       f"{kind} binary: {len(blob)} B", cat="EXEC")]
    return [_f("FMT-01", f"Нативная библиотека: неизвестный формат ({label})", "low", 0.3,
               "no ELF/PE/Mach-O magic", cat="FMT")]


def _scan_jinja(text: str, label: str) -> list[dict]:
    """Jinja2-шаблоны (промпты/конфиги), поставляемые с моделью: SSTI."""
    out: list[dict] = []
    if not any(m in text for m in JINJA_MARK):
        return out
    hits = [h for h in JINJA_DANGER if h in text]
    if hits:
        out.append(_f("INJ-01", f"Опасные конструкции в Jinja-шаблоне ({label})", "high", 0.8,
                      "hints: " + ", ".join(hits[:5]), cat="INJ"))
    return out


def _scan_sitepath(text: str, label: str) -> list[dict]:
    """`.pth` файл из site-packages — код исполняется при старте интерпретатора."""
    hits = [h for h in ("import ", "exec(", "eval(", "os.system", "subprocess", "__import__")
            if h in text]
    if hits:
        return [_f("EXEC-02", f"Исполняемый .pth-хук ({label})", "critical", 0.9,
                   "hints: " + ", ".join(hits[:4]), cat="EXEC")]
    return []


def _scan_script(text: str, label: str) -> list[dict]:
    """Скрипты (.sh/.ps1/.bat): запуск скачанного кода, обфускация, внешние URL."""
    out: list[dict] = []
    low = text.lower()
    if PIPE_TO_SHELL.search(text):
        out.append(_f("EXEC-02", f"Запуск скачанного кода в скрипте ({label})", "high", 0.85,
                      "curl|bash / download-and-execute", cat="EXEC"))
    hits = [h for h in SCRIPT_EXEC if h in low]
    if hits:
        out.append(_f("EXEC-02", f"Исполняемые конструкции в скрипте ({label})", "high", 0.7,
                      "hints: " + ", ".join(hits[:5]), cat="EXEC"))
    if "http://" in low or "https://" in low:
        out.append(_f("INT-03", f"Внешние URL в скрипте ({label})", "medium", 0.5,
                      "внешний источник может подтягивать код/данные", cat="INT"))
    return out


def _scan_notebook(blob: bytes, label: str) -> list[dict]:
    """Jupyter notebook: код ячеек исполняется при запуске (и часто при открытии)."""
    out: list[dict] = []
    try:
        nb = json.loads(_btext(blob))
    except Exception as exc:  # noqa: BLE001
        return [_f("FMT-01", f"Notebook: нечитаемый JSON ({label})", "low", 0.3, str(exc), cat="FMT")]
    code: list[str] = []
    md: list[str] = []
    for cell in (nb.get("cells") or []):
        src = "".join(cell.get("source") or [])
        if cell.get("cell_type") == "code":
            code.append(src)
        elif cell.get("cell_type") == "markdown":
            md.append(src)
    text = "\n".join(code)
    if code:
        # NB: общий _scan_python здесь не годится — PY_CODE_HINTS ловит обычный "import "
        hits = [h for h in ("os.system", "subprocess", "eval(", "exec(", "__import__",
                            "socket.", "urlopen", "requests.get", "pty.spawn") if h in text]
        if hits:
            out.append(_f("EXEC-02", f"Исполняемый код в notebook ({label})", "high", 0.75,
                          "hints: " + ", ".join(hits[:5]), cat="EXEC"))
        shell = [h for h in NOTEBOOK_SHELL if h in text.lower()]
        if shell:
            out.append(_f("INT-03", f"Shell-команды в notebook ({label})", "medium", 0.5,
                          "hints: " + ", ".join(shell[:4]), cat="INT"))
    out.extend(_scan_card("\n".join(md), label))
    return out


def _scan_dataset(blob: bytes, label: str) -> list[dict]:
    """Parquet/Arrow/Feather: pickle-потоки и внешние ссылки в метаданных."""
    out: list[dict] = []
    if not (blob[:4] == b"PAR1" or blob[:6] == b"ARROW1" or blob[:4] == b"FEA1"):
        out.append(_f("FMT-01", f"Датасет: неизвестная сигнатура ({label})", "low", 0.3,
                      "not parquet/arrow/feather", cat="FMT"))
        return out
    has_pickle = any(m in blob for m in (b"\x80\x04", b"\x80\x05"))
    marks = [g for g in (b"posix", b"system", b"subprocess", b"builtins", b"os.system") if g in blob]
    if has_pickle and marks:
        out.append(_f("EXEC-02", f"Pickle-поток в метаданных датасета ({label})", "critical", 0.85,
                      "pickle stream + " + ", ".join(m.decode() for m in marks[:3]), cat="EXEC"))
    if b"http://" in blob or b"https://" in blob:
        out.append(_f("INT-03", f"Внешние URL в метаданных датасета ({label})", "medium", 0.5,
                      "внешний источник", cat="INT"))
    return out


def _scan_flatbuffer_ops(blob: bytes, label: str, kind: str) -> list[dict]:
    """TFLite/CoreML: нестандартные (custom/python) операции."""
    low = blob.lower()
    hits = [h for h in (b"flex", b"custom", b"pywrap", b"python") if h in low]
    if hits:
        return [_f("EXEC-02", f"{kind}: кастомные/нестандартные операции ({label})", "high", 0.6,
                   "custom ops: " + ", ".join(h.decode() for h in hits[:4]), cat="EXEC")]
    return []


def _scan_savedmodel(blob: bytes, label: str) -> list[dict]:
    """TensorFlow SavedModel: ссылки на Python-код внутри графа."""
    low = blob.lower()
    hits = [h for h in (b"py_function", b"pyfunc", b"tf.py_func", b"python_op", b"pywrap")
            if h in low]
    if hits:
        return [_f("EXEC-01", f"SavedModel со ссылкой на Python-код ({label})", "high", 0.7,
                   "py_function/PyFunc", cat="EXEC")]
    return []


def _scan_pmml(text: str, label: str) -> list[dict]:
    """PMML: расширения с исполняемым кодом (Java/Python/Script)."""
    low = text.lower()
    hits = [h for h in ("<extension", "java", "script", "python", "external") if h in low]
    if hits:
        return [_f("EXEC-02", f"PMML: расширяемый код/внешние ссылки ({label})", "medium", 0.5,
                   "hints: " + ", ".join(hits[:4]), cat="EXEC")]
    return []


def _scan_mlflow(path: Path) -> list[dict]:
    """MLflow-модель (zip с MLmodel): код и внешние источники в метаданных."""
    out: list[dict] = []
    try:
        zf = zipfile.ZipFile(path)
        names = [n for n in zf.namelist()]
    except Exception:  # noqa: BLE001
        return out
    for n in names:
        ln = n.lower()
        try:
            if ln.endswith(".py"):
                out.extend(_scan_python(_btext(zf.read(n)), f"{path.name}:{n}"))
            elif ln.endswith((".yaml", ".yml", ".json", ".txt")):
                out.extend(_scan_python(_btext(zf.read(n)), f"{path.name}:{n}"))
                t = _btext(zf.read(n))
                if "http://" in t or "https://" in t:
                    out.append(_f("INT-03", f"Внешние URL в метаданных MLflow ({path.name})",
                                  "medium", 0.5, f"{n}", cat="INT"))
        except Exception:  # noqa: BLE001
            continue
    return out


def _scan_zip(path: Path) -> tuple[list[dict], str]:
    out: list[dict] = []
    fmt = "zip"
    try:
        zf = zipfile.ZipFile(path)
        names = zf.namelist()
    except Exception as exc:  # noqa: BLE001
        return [_f("FMT-01", "Повреждённый zip-контейнер", "low", 0.4, str(exc), cat="FMT")], fmt
    low = [_norm_name(n) for n in names]
    if any(n.endswith("mar-inf/manifest.json") for n in low):
        fmt = "torchserve-mar"
    norm = [_norm_name(n) for n in names]
    is_mlflow = any(n == "mlmodel" or n.endswith("/mlmodel") for n in norm)
    code_dir = [n for n in names if _norm_name(n).startswith("code/")]
    ts_like = bool(code_dir) and (any(n == "version" for n in norm)
                                  or any(n.endswith("constants.pkl") for n in norm))
    code_norm = {_norm_name(n) for n in code_dir}
    has_py = [n for n in names if Path(n).suffix.lower() in CODE_EXT
              and _norm_name(n) not in code_norm]      # TorchScript code/ разбирается отдельно
    if has_py and not ts_like:
        risky = []
        for n in has_py[:20]:
            try:
                if any(h in _btext(zf.read(n)) for h in PY_CODE_HINTS):
                    risky.append(n)
            except Exception:  # noqa: BLE001
                continue
        if risky:
            out.append(_f("EXEC-02", f"Опасный Python-код внутри контейнера ({', '.join(risky[:4])})",
                          "high", 0.85, "files: " + ", ".join(risky[:6])))
        else:
            out.append(_f("EXEC-02", f"Python-код внутри контейнера ({', '.join(has_py[:4])})",
                          "info", 0.5, "files: " + ", ".join(has_py[:6])))
    for n in names:
        if _norm_name(n).endswith(".pth"):
            try:
                text = _btext(zf.read(n))
            except Exception:  # noqa: BLE001
                continue
            hits = _scan_sitepath(text, f"{path.name}:{n}")
            if hits:
                out.extend(hits)
                out.append(_f("INT-04", f"Архив содержит install-хук ({n})", "high", 0.75,
                              ".pth исполняется при старте интерпретатора", cat="INT"))
    if fmt == "torchserve-mar" and has_py:
        out.append(_f("EXEC-01", "TorchServe .mar с handler-кодом (исполнение при serve)",
                      "critical", 0.9, "MAR-INF + handler.py"))
    if any(n in ("mar-inf/manifest.json",) for n in low):
        pass
    code_files = [n for n in names
                  if _norm_name(n).startswith("code/") and _norm_name(n).endswith((".py", ".pyi"))]
    constants = [n for n in names if _norm_name(n).endswith("constants.pkl")]
    if code_files or constants:
        # Легитимный TorchScript (torch.jit) тоже хранит код в code/ — это НЕ закладка.
        suspicious: list[str] = []
        ts_markers = ("__torch__", "torch.jit", "torch._C", "torch/csrc", "TorchScript")
        for n in code_files[:20]:
            try:
                t = _btext(zf.read(n))
            except Exception:  # noqa: BLE001
                continue
            if ("os.system" in t or "subprocess" in t or "socket:" in t
                    or [h for h in PY_CODE_HINTS if h in t]):
                suspicious.append(n)
        bad_const = False
        for n in constants[:3]:
            try:
                raw = zf.read(n)
            except Exception:  # noqa: BLE001
                continue
            if any(g in raw for g in (b"posix", b"os.system", b"subprocess", b"system",
                                      b"Popen", b"eval", b"exec")):
                bad_const = True
        if suspicious:
            out.append(_f("EXEC-03", "torch.package/TorchScript с исполняемым кодом внутри архива",
                          "high", 0.85, "code/: " + ", ".join(suspicious[:3])))
            for n in suspicious[:5]:
                try:
                    out.extend(_scan_python(_btext(zf.read(n)), f"{path.name}:{n}"))
                except Exception:  # noqa: BLE001
                    pass
        elif bad_const:
            out.append(_f("EXEC-03", "torch.package: опасный pickle в constants.pkl",
                          "high", 0.8, "constants.pkl + os/system", cat="FMT"))
        elif not (code_files and all(
                any(m in _btext(zf.read(n)) for m in ts_markers)
                for n in code_files[:20] if True)):
            if code_files:
                out.append(_f("EXEC-03", "torch.package/TorchScript со сторонним кодом в архиве",
                              "medium", 0.6, "code/ без признаков TorchScript"))
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
    if "Lambda" in text or "__reduce__" in text:
        out.append(_f("EXEC-05", f"HDF5: признаки Lambda/__reduce__ ({label})",
                      "high", 0.7, "lambda/reduce strings"))
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
        external = b"external" in blob or b"data_location" in blob
        if external:
            out.append(_f("EXEC-06", f"ONNX external_data с location ({label}) — риск path traversal/URL",
                          "high", 0.75, "external + location"))
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


def _scan_safetensors(blob: bytes, label: str, total_size: int | None = None) -> list[dict]:
    import struct
    out: list[dict] = []
    size = total_size or len(blob)   # при чтении префиксом границы считаем по реальному размеру
    if len(blob) < 8:
        return [_f("FMT-01", f"SafeTensors: файл слишком мал ({label})", "medium", 0.5, "len<8", cat="FMT")]
    (hlen,) = struct.unpack("<Q", blob[:8])
    if hlen <= 0 or hlen + 8 > size:
        return [_f("FMT-01", f"SafeTensors: некорректная длина заголовка ({label})",
                   "high", 0.8, f"header_len={hlen}", cat="FMT")]
    try:
        header = json.loads(blob[8:8 + hlen].decode("utf-8", "replace"))
    except Exception as exc:  # noqa: BLE001
        return [_f("FMT-01", f"SafeTensors: нечитаемый заголовок ({label})", "high", 0.8, str(exc), cat="FMT")]
    meta = header.get("__metadata__") or {}
    if isinstance(meta, dict):
        meta_blob = " ".join(str(v) for v in meta.values()).lower()
        hits = [h for h in ("curl ", "wget ", "| bash", "| sh", "os.system", "subprocess",
                            "eval(", "__import__", "base64 -d", "powershell", "iex(")
                if h in meta_blob]
        if hits:
            out.append(_f("EXEC-02", f"SafeTensors: полезная нагрузка в метаданных ({label})",
                          "high", 0.7, "metadata: " + ", ".join(hits[:4]), cat="EXEC"))
    data_start = 8 + hlen
    data_len = size - data_start
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


INSTALL_FILES = ("requirements.txt", "setup.py", "pyproject.toml", "conda.yaml",
                 "environment.yml", "Makefile", ".pth")
NATIVE_MAGIC = {b"\x7fELF": "ELF", b"MZ": "PE", b"\xcf\xfa\xed\xfe": "Mach-O",
                b"\xca\xfe\xba\xbe": "Mach-O (fat)", b"\xfe\xed\xfa\xcf": "Mach-O"}
JINJA_MARK = ("{{", "{%")
JINJA_DANGER = ("__class__", "__mro__", "__globals__", "__subclasses__", "__builtins__",
                "cycler", "lipsum", "config", "request", "os.popen", "subprocess",
                "self.__init__", "attr(")


def _scan_zip_extra(path: Path) -> list[dict]:
    out: list[dict] = []
    try:
        zf = zipfile.ZipFile(path)
    except Exception:  # noqa: BLE001
        return out
    names_low = [_norm_name(n) for n in zf.namelist()]
    is_mlflow = any(n == "mlmodel" or n.endswith("/mlmodel") for n in names_low)
    hits = [n for n in names_low if Path(n).name in INSTALL_FILES]
    if hits and is_mlflow:
        hits = []      # requirements.txt/conda.yaml — штатная часть MLflow-модели
    if hits:
        out.append(_f("INT-04", f"Архив содержит install-файлы ({', '.join(hits[:4])})",
                      "high", 0.75, "install hooks могут выполнять код при установке", cat="INT"))
    # trailing-данные после EOCD (скрытый канал / полиглот)
    try:
        blob = path.read_bytes()
        pos = blob.rfind(b"PK\x05\x06")
        if pos != -1 and pos + 22 <= len(blob):
            (clen,) = __import__("struct").unpack_from("<H", blob, pos + 20)
            end = pos + 22 + clen
            if len(blob) > end:
                out.append(_f("STEG-01", f"Zip: данные после EOCD ({len(blob) - end} байт)",
                              "medium", 0.6, "trailing after zip end", cat="STEG"))
    except Exception:  # noqa: BLE001
        pass
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
    text_members = (".sh", ".bash", ".ps1", ".bat", ".cmd", ".py", ".json", ".yaml", ".yml",
                    ".txt", ".cfg", ".toml")
    for m in tf.getmembers():
        low = m.name.lower()
        if m.isfile() and low.endswith(text_members) and m.size <= 2 * 1024 * 1024:
            try:
                fh = tf.extractfile(m)
                text = _btext(fh.read()) if fh else ""
            except Exception:  # noqa: BLE001
                text = ""
            if not text:
                continue
            if low.endswith((".sh", ".bash", ".ps1", ".bat", ".cmd")):
                out.extend(_scan_script(text, f"{path.name}:{m.name}"))
            elif low.endswith(".py"):
                out.extend(_scan_python(text, f"{path.name}:{m.name}"))
            elif low.endswith((".json", ".yaml", ".yml")):
                if low.endswith(".json"):
                    out.extend(_scan_json(text, f"{path.name}:{m.name}"))
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
    servers = data.get("mcpServers")
    spawns = []
    if isinstance(servers, dict):
        for srv, cfg in servers.items():
            if isinstance(cfg, dict) and ("command" in cfg or "args" in cfg):
                spawns.append(srv)
    # критично только реальное порождение процессов (command/args); простой URL/transport — нет
    if spawns or ('"command"' in blob and '"args"' in blob):
        out.append(_f("AGT-01", f"MCP/agent-манифест с запуском команд ({label})", "critical", 0.8,
                      "mcpServers/command", cat="AGT"))
    if '"tools"' in blob:
        bad = [p for p in ("ignore", "execute", "read file", "/etc/", "send ", "exfiltrate")
               if p in blob]
        if bad:
            out.append(_f("INJ-04", f"Tool-схема с подозрительными описаниями ({label})", "high", 0.6,
                          "terms: " + ", ".join(bad), cat="INJ"))
    return out


def _scan_steg_json(data: dict, text: str, label: str) -> list[dict]:
    out: list[dict] = []
    if "http://" in text or "https://" in text:
        out.append(_f("INT-03", f"Внешние URL в конфиге/метаданных ({label})", "medium", 0.6,
                      "внешний источник может подтягивать код/данные", cat="INT"))
    import re as _re
    for v in _re.findall(r'"([^"]{200,})"', text):
        charset = set(v)
        if (charset <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n")) or \
           (charset <= set("0123456789abcdefABCDEF")):
            out.append(_f("STEG-02", f"Высокоэнтропийная строка в метаданных ({label})",
                          "medium", 0.55, f"len={len(v)}", cat="STEG"))
            break
    return out


IMG_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"}


def _scan_image_polyglot(blob: bytes, label: str) -> list[dict]:
    out: list[dict] = []
    if any(m in blob for m in (b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05")) and \
       blob[:4] == b"PK\x03\x04":
        pass
    if any(m in blob for m in (b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05")):
        out.append(_f("STEG-03", f"Изображение содержит pickle-поток ({label})",
                      "high", 0.7, "polyglot image+pickle", cat="STEG"))
    if blob[:4] == b"PK\x03\x04":
        out.append(_f("STEG-03", f"Изображение является zip-контейнером ({label})",
                      "medium", 0.6, "polyglot image+zip", cat="STEG"))
    return out


def _norm_name(name: str) -> str:
    """Имя члена архива без служебного префикса torch ("archive/")."""
    low = name.lower()
    return low[len("archive/"):] if low.startswith("archive/") else low


def detect(path: Path, head: bytes) -> str:
    ext = path.suffix.lower()
    if head.startswith(ZIP_MAGIC):
        try:
            names = [_norm_name(n) for n in zipfile.ZipFile(path).namelist()]
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
        if any(n == "mlmodel" or n.endswith("/mlmodel") for n in names):
            return "mlflow"
        if any(n.endswith("saved_model.pb") for n in names):
            return "savedmodel"
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
    if ext in CODE_EXT or ext in NOTEBOOK_EXT:
        return "python" if ext not in NOTEBOOK_EXT else "notebook"
    if ext in SCRIPT_EXT:
        return "script"
    if ext in DATASET_EXT:
        return "dataset"
    if ext == ".tflite" or head[:4] == b"TFL3":
        return "tflite"
    if ext in (".mlmodel", ".mlpackage"):
        return "coreml"
    if ext in (".j2", ".jinja", ".jinja2"):
        return "jinja"
    if ext in (".so", ".dll", ".dylib", ".node", ".a", ".o"):
        return "native"
    if ext == ".pb":
        return "savedmodel"
    if ext == ".pth" and head.lstrip()[:7] in (b"import ", b"exec(", b"eval("):
        return "sitepath"      # текстовый .pth-хук, а не веса torch
    if ext == ".pmml":
        return "pmml"
    if ext in (".xml", ".ovpn"):
        return "xml"
    if ext in (".json", ".yaml", ".yml"):
        return "config"
    if ext in (".md", ".txt", ".rst"):
        return "card"
    if ext in IMG_EXT:
        return "image"
    if head[:2] in (b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05"):
        return "pickle"
    return "unknown"


MAX_STATIC_BYTES = 64 * 1024 * 1024   # крупные файлы читаем префиксом (тело проверяет динамика)


def _read_bounded(path: Path, limit: int = MAX_STATIC_BYTES) -> bytes:
    with path.open("rb") as fh:
        return fh.read(limit)


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
        if fmt in ("torchserve-mar", "keras", "torch-package", "torch-zip", "zip",
                   "mlflow", "savedmodel") and zipfile.is_zipfile(path):
            findings.extend(_scan_zip_extra(path))
            f2, real = _scan_zip(path)
            findings.extend(f2)
            if fmt == "mlflow":
                findings.extend(_scan_mlflow(path))
            if fmt == "savedmodel":
                findings.extend(_scan_savedmodel(_read_bounded(path), path.name))
            fmt = real if real != "zip" else fmt
        elif fmt == "python":
            findings.extend(_scan_python(_btext(_read_bounded(path)), path.name))
        elif fmt == "model-as-code":
            text = _btext(_read_bounded(path))
            findings.append(_f("EXEC-01", f"Model-as-code артефакт ({path.name})", "high", 0.9,
                               "исполняемый артефакт"))
            findings.extend(_scan_python(text, path.name))
        elif fmt == "onnx":
            findings.extend(_scan_onnx(_read_bounded(path), path.name))
        elif fmt == "hdf5":
            findings.extend(_scan_hdf5(_read_bounded(path), path.name))
        elif fmt == "gguf":
            findings.extend(_scan_gguf(_read_bounded(path), path.name))
        elif fmt == "safetensors":
            findings.extend(_scan_safetensors(_read_bounded(path), path.name, path.stat().st_size))
        elif fmt == "tar":
            findings.extend(_scan_tar(path))
        elif fmt == "xml":
            findings.extend(_scan_xml(_read_bounded(path), path.name))
        elif fmt == "config":
            blob = _read_bounded(path)
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
                    findings.extend(_scan_steg_json(data, text, path.name))
                    if any(k in data for k in ("added_tokens", "normalizer", "pre_tokenizer", "model")):
                        findings.extend(_scan_tokenizer(data, path.name))
                    findings.extend(_scan_tools(data, path.name))
        elif fmt == "card":
            findings.extend(_scan_card(_btext(_read_bounded(path)), path.name))
        elif fmt == "notebook":
            findings.extend(_scan_notebook(_read_bounded(path), path.name))
        elif fmt == "script":
            findings.extend(_scan_script(_btext(_read_bounded(path)), path.name))
        elif fmt == "dataset":
            findings.extend(_scan_dataset(_read_bounded(path), path.name))
        elif fmt == "tflite":
            findings.extend(_scan_flatbuffer_ops(_read_bounded(path), path.name, "TFLite"))
        elif fmt == "coreml":
            findings.extend(_scan_flatbuffer_ops(_read_bounded(path), path.name, "CoreML"))
        elif fmt == "pmml":
            findings.extend(_scan_xml(_read_bounded(path), path.name))
            findings.extend(_scan_pmml(_btext(_read_bounded(path)), path.name))
        elif fmt == "savedmodel":
            findings.extend(_scan_savedmodel(_read_bounded(path), path.name))
        elif fmt == "jinja":
            findings.extend(_scan_jinja(_btext(_read_bounded(path)), path.name))
        elif fmt == "native":
            findings.extend(_scan_native(_read_bounded(path), path.name))
        elif fmt == "sitepath":
            findings.extend(_scan_sitepath(_btext(_read_bounded(path)), path.name))
        elif fmt == "image":
            findings.extend(_scan_image_polyglot(_read_bounded(path), path.name))
    except Exception as exc:  # noqa: BLE001
        findings.append(_f("FMT-01", f"Ошибка разбора {fmt}", "low", 0.3, str(exc), cat="FMT"))
    # проверка несоответствия расширения реальному формату
    ext = path.suffix.lower()
    if fmt in ("python", "torchserve-mar") and ext not in (".py", ".mar"):
        findings.append(_f("FMT-02", f"Несоответствие расширения и формата: {ext} -> {fmt}",
                           "medium", 0.7, f"ext={ext} real={fmt}", cat="FMT"))
    return {"format": fmt, "findings": findings}
