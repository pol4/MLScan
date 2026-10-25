#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MLScan format adapters (Wave 1): детект формата и статические проверки
на исполнение кода для model-as-code, Keras/SavedModel, ONNX, HDF5, GGUF/шаблонов.

Только stdlib. Возвращает находки в формате, совместимом с `mlscan_poc`:
{check_id, category, title, severity, confidence, evidence}.
"""
from __future__ import annotations

import io
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


ARCHIVE_EXT = (".zip", ".whl", ".jar", ".tar", ".tar.gz", ".tgz", ".mar")
COMPRESSED_EXT = (".gz", ".bz2", ".xz")
UNSUPPORTED_MAGIC = {b"7z\xbc\xaf\x27\x1c": "7z", b"Rar!\x1a\x07": "rar",
                     b"\x28\xb5\x2f\xfd": "zstd"}
# Секреты в артефакте: ключи, токены, приватные ключи (утечка через репозиторий модели)
SECRET_PATTERNS = (
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("huggingface_token", re.compile(r"hf_[A-Za-z0-9]{20,}")),
    ("github_token", re.compile(r"ghp_[A-Za-z0-9]{30,}")),
    ("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("openai_key", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("generic_secret", re.compile(r"(?i)(api[_-]?key|secret|password)\s*[:=]\s*['\"][^'\"]{12,}['\"]")),
)


def _scan_secrets(text: str, label: str) -> list[dict]:
    """Поиск секретов/токенов: утечка ключей вместе с моделью."""
    hits = [name for name, rx in SECRET_PATTERNS if rx.search(text)]
    if hits:
        return [_f("SEC-01", f"Секреты/токены в артефакте ({label})", "high", 0.8,
                   "найдено: " + ", ".join(sorted(set(hits))), cat="SEC")]
    return []


def _scan_jsonl(blob: bytes, label: str) -> list[dict]:
    """JSONL-датасеты (инструкции/промпты): инъекции в тексте и внешние ссылки."""
    out: list[dict] = []
    text = _btext(blob)
    out.extend(_scan_card(text, label))
    out.extend(_scan_secrets(text, label))
    if "http://" in text or "https://" in text:
        out.append(_f("INT-03", f"Внешние URL в датасете ({label})", "low", 0.4,
                      "внешний источник", cat="INT"))
    return out


CSV_FORMULA = re.compile(r"(^|[,\t;])\s*[=+@][^,\n]{0,80}?"
                         r"(cmd|powershell|rundll32|HYPERLINK|DDE|/c |\\c)",
                         re.IGNORECASE)


def _scan_csv(blob: bytes, label: str) -> list[dict]:
    """CSV/TSV-датасеты: формульные инъекции (исполнение при открытии в таблицах)."""
    out: list[dict] = []
    text = _btext(blob)
    if CSV_FORMULA.search(text):
        out.append(_f("INJ-06", f"Формульная инъекция в датасете ({label})", "high", 0.7,
                      "=cmd|.../HYPERLINK/DDE", cat="INJ"))
    out.extend(_scan_secrets(text, label))
    if "http://" in text or "https://" in text:
        out.append(_f("INT-03", f"Внешние URL в датасете ({label})", "low", 0.4,
                      "внешний источник", cat="INT"))
    return out


def _scan_msgpack(blob: bytes, label: str) -> list[dict]:
    """MessagePack (MLflow и др.): внутри может лежать pickle-поток."""
    out: list[dict] = []
    marks = [g for g in (b"posix", b"os.system", b"subprocess", b"__reduce__", b"builtins")
             if g in blob]
    if any(m in blob for m in (b"\x80\x04", b"\x80\x05")) and marks:
        out.append(_f("EXEC-02", f"Pickle-поток внутри MessagePack ({label})", "high", 0.7,
                      "pickle + " + ", ".join(m.decode() for m in marks[:3]), cat="EXEC"))
    return out


def _scan_compressed_pickle(blob: bytes, label: str) -> list[dict]:
    """Разбор pickle внутри сжатого потока: опасные глобалы без исполнения."""
    import pickletools
    out: list[dict] = []
    try:
        text = blob.decode("latin1")
    except Exception:  # noqa: BLE001
        text = ""
    globals_found: list[str] = []
    try:
        for op, _arg, _pos in pickletools.genops(io.BytesIO(blob)):
            if op.name in ("GLOBAL", "STACK_GLOBAL"):
                mod, name = str(_arg).split(" ", 1) if _arg else ("", "")
                globals_found.append(f"{mod} {name}")
    except Exception:  # noqa: BLE001
        pass
    hits = [g for g in globals_found if g.split()[0] in (
        "posix", "nt", "os", "subprocess", "builtins", "__builtin__", "sys", "socket",
        "shutil", "urllib", "requests", "ctypes", "runpy")]
    if hits:
        out.append(_f("A-01", f"Опасный глобал в сжатом pickle ({label})", "critical", 0.9,
                      "globals: " + ", ".join(sorted(set(hits))[:5]), cat="A"))
    elif globals_found:
        out.append(_f("A-19", f"Неизвестные глобалы в сжатом pickle ({label})", "low", 0.4,
                      ", ".join(sorted(set(globals_found))[:4]), cat="A"))
    if not out and any(m in blob for m in (b"os.system", b"subprocess", b"eval(")):
        out.append(_f("A-20", f"Подозрительные строки в сжатом pickle ({label})", "medium", 0.5,
                      "substrings", cat="A"))
    _ = text
    return out


def _decompress(path: Path, limit: int = 64 * 1024 * 1024) -> bytes | None:
    """Распаковка .gz/.bz2/.xz с ограничением (payload может быть сжатым)."""
    import bz2
    import gzip
    import lzma
    try:
        with path.open("rb") as fh:
            raw = fh.read(limit)
        if path.suffix.lower() == ".gz":
            return gzip.decompress(raw)[:limit]
        if path.suffix.lower() == ".bz2":
            return bz2.decompress(raw)[:limit]
        if path.suffix.lower() == ".xz":
            return lzma.decompress(raw)[:limit]
    except Exception:  # noqa: BLE001
        return None
    return None


def _scan_html(blob: bytes, label: str) -> list[dict]:
    """HTML/SVG в пакете модели: скрипты и обработчики (XSS при рендере карточки)."""
    out: list[dict] = []
    text = _btext(blob)
    low = text.lower()
    xss = [m for m in ("<script", "onerror=", "onload=", "javascript:", "<iframe",
                       "document.cookie", "xmlhttprequest", "fetch(") if m in low]
    if xss:
        out.append(_f("INJ-05", f"HTML/JS в документе ({label}) — XSS при рендере", "high", 0.75,
                      "markers: " + ", ".join(xss[:5]), cat="INJ"))
    # namespace-декларации (www.w3.org) — не внешние источники
    rest = low.replace("http://www.w3.org", "").replace("https://www.w3.org", "")
    if "http://" in rest or "https://" in rest:
        out.append(_f("INT-03", f"Внешние URL в документе ({label})", "low", 0.4,
                      "внешний источник", cat="INT"))
    return out


def _scan_dockerfile(text: str, label: str) -> list[dict]:
    """Dockerfile рядом с моделью: загрузка и запуск кода при сборке образа."""
    out: list[dict] = []
    low = text.lower()
    if PIPE_TO_SHELL.search(text) or "add http" in low:
        out.append(_f("EXEC-02", f"Dockerfile скачивает и исполняет код ({label})", "high", 0.8,
                      "curl|bash / ADD http", cat="EXEC"))
    else:
        hits = [h for h in ("run curl", "run wget", "&& curl", "&& wget", "chmod +x",
                            "chown root", "setcap", "pip install git+http") if h in low]
        if hits:
            out.append(_f("EXEC-02", f"Dockerfile: загрузка/исполнение кода ({label})", "medium", 0.55,
                          "hints: " + ", ".join(hits[:4]), cat="EXEC"))
    if "http://" in low or "https://" in low:
        out.append(_f("INT-03", f"Внешние URL в Dockerfile ({label})", "medium", 0.5,
                      "внешний источник", cat="INT"))
    return out


def _scan_nested_archive(data: bytes, label: str, depth: int = 0) -> list[dict]:
    budget = _Budget()
    """Вложенные архивы (zip в zip): install-хуки, код и pickle-потоки внутри."""
    out: list[dict] = []
    if depth > 2:
        return out
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception:  # noqa: BLE001
        return out
    for info in zf.infolist():
        nm = _norm_name(info.filename)
        if info.file_size > 8 * 1024 * 1024:
            continue
        try:
            blob = _read_member(zf, info, budget)[0]
        except Exception:  # noqa: BLE001
            continue
        if nm.endswith(ARCHIVE_EXT):
            out.extend(_scan_nested_archive(blob, f"{label}:{info.filename}", depth + 1))
        elif nm.endswith(".pth"):
            hits = _scan_sitepath(_btext(blob), f"{label}:{info.filename}")
            if hits:
                out.extend(hits)
                out.append(_f("INT-04", f"Вложенный архив содержит install-хук ({info.filename})",
                              "high", 0.75, ".pth во вложенном архиве", cat="INT"))
        elif nm.endswith(".py"):
            if any(h in _btext(blob) for h in PY_CODE_HINTS):
                out.append(_f("EXEC-02", f"Опасный Python-код во вложенном архиве ({info.filename})",
                              "high", 0.8, f"{label}:{info.filename}", cat="EXEC"))
        elif any(Path(nm).name == f for f in INSTALL_FILES):
            out.append(_f("INT-04", f"Вложенный архив содержит install-файлы ({info.filename})",
                          "high", 0.7, f"{label}:{info.filename}", cat="INT"))
    return out


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
    budget = _Budget()
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
                out.extend(_scan_python(_btext(_read_member(zf, zf.getinfo(n), budget)[0]), f"{path.name}:{n}"))
            elif ln.endswith((".yaml", ".yml", ".json", ".txt")):
                out.extend(_scan_python(_btext(_read_member(zf, zf.getinfo(n), budget)[0]), f"{path.name}:{n}"))
                t = _btext(_read_member(zf, zf.getinfo(n), budget)[0])
                if "http://" in t or "https://" in t:
                    out.append(_f("INT-03", f"Внешние URL в метаданных MLflow ({path.name})",
                                  "medium", 0.5, f"{n}", cat="INT"))
        except Exception:  # noqa: BLE001
            continue
    return out


def _scan_zip(path: Path) -> tuple[list[dict], str]:
    budget = _Budget()
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
                if any(h in _btext(_read_member(zf, zf.getinfo(n), budget)[0]) for h in PY_CODE_HINTS):
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
        if _norm_name(n).endswith(ARCHIVE_EXT):
            try:
                inner = _read_member(zf, zf.getinfo(n), budget)[0]
            except Exception:  # noqa: BLE001
                continue
            if len(inner) <= 16 * 1024 * 1024:
                out.extend(_scan_nested_archive(inner, f"{path.name}:{n}"))
    for n in names:
        if _norm_name(n).endswith(".pth"):
            try:
                text = _btext(_read_member(zf, zf.getinfo(n), budget)[0])
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
                t = _btext(_read_member(zf, zf.getinfo(n), budget)[0])
            except Exception:  # noqa: BLE001
                continue
            if ("os.system" in t or "subprocess" in t or "socket:" in t
                    or [h for h in PY_CODE_HINTS if h in t]):
                suspicious.append(n)
        bad_const = False
        for n in constants[:3]:
            try:
                raw = _read_member(zf, zf.getinfo(n), budget)[0]
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
                    out.extend(_scan_python(_btext(_read_member(zf, zf.getinfo(n), budget)[0]), f"{path.name}:{n}"))
                except Exception:  # noqa: BLE001
                    pass
        elif bad_const:
            out.append(_f("EXEC-03", "torch.package: опасный pickle в constants.pkl",
                          "high", 0.8, "constants.pkl + os/system", cat="FMT"))
        elif not (code_files and all(
                any(m in _btext(_read_member(zf, zf.getinfo(n), budget)[0]) for m in ts_markers)
                for n in code_files[:20] if True)):
            if code_files:
                out.append(_f("EXEC-03", "torch.package/TorchScript со сторонним кодом в архиве",
                              "medium", 0.6, "code/ без признаков TorchScript"))
    # конфиги внутри zip (Keras .keras, прочее)
    for n in names:
        ln = n.lower()
        if ln.endswith((".json", ".yaml", ".yml")):
            try:
                txt = _btext(_read_member(zf, zf.getinfo(n), budget)[0])
            except Exception:  # noqa: BLE001
                continue
            if ln.endswith(".json"):
                out.extend(_scan_json(txt, f"{path.name}:{n}"))
        if ln.endswith(".py"):
            try:
                out.extend(_scan_python(_btext(_read_member(zf, zf.getinfo(n), budget)[0]), f"{path.name}:{n}"))
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
    if blob[:2] in (b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05"):
        return [_f("FMT-02", f"Несоответствие расширения и формата: .safetensors -> pickle ({label})",
                   "high", 0.8, "pickle magic под расширением safetensors", cat="FMT")]
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
    seen_names: dict[str, int] = {}
    for n in names_low:
        seen_names[n] = seen_names.get(n, 0) + 1
    dups = sorted(n for n, c in seen_names.items() if c > 1)
    if dups:
        out.append(_f("FMT-12", f"Дубликаты записей в архиве ({', '.join(dups[:3])})", "high", 0.7,
                      "parser differential: разные загрузчики читают разные копии", cat="FMT"))
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
        tf = tarfile.open(path, errorlevel=0)
    except Exception:  # noqa: BLE001
        return [_f("FMT-01", "Повреждённый tar-архив", "low", 0.3, str(path.name), cat="FMT")]
    total_u = 0
    bomb = False
    try:
        member = tf.next()
        while member is not None:
            if member.name.startswith("/") or ".." in Path(member.name).parts:
                out.append(_f("FMT-03", f"Tar: подозрительный путь ({member.name})", "high", 0.8,
                              "path traversal/absolute", cat="FMT"))
            if member.issym() or member.islnk():
                out.append(_f("FMT-05", f"Tar: ссылка/жёсткая ссылка ({member.name})", "high", 0.7,
                              "symlink/hardlink", cat="FMT"))
            # текстовые члены архива (скрипты/код/конфиги) — тоже проверяем
            low = member.name.lower()
            if member.isfile() and low.endswith((".sh", ".bash", ".ps1", ".bat", ".cmd", ".py",
                                                 ".json", ".yaml", ".yml", ".txt")) \
                    and 0 < member.size <= 2 * 1024 * 1024:
                try:
                    fh = tf.extractfile(member)
                    text = _btext(fh.read()) if fh else ""
                except Exception:  # noqa: BLE001
                    text = ""
                if text:
                    if low.endswith((".sh", ".bash", ".ps1", ".bat", ".cmd")):
                        out.extend(_scan_script(text, f"{path.name}:{member.name}"))
                    elif low.endswith(".py"):
                        out.extend(_scan_python(text, f"{path.name}:{member.name}"))
                    elif low.endswith(".json"):
                        out.extend(_scan_json(text, f"{path.name}:{member.name}"))
                        out.extend(_scan_secrets(text, f"{path.name}:{member.name}"))
                    else:
                        out.extend(_scan_secrets(text, f"{path.name}:{member.name}"))
            total_u += member.size
            if total_u > 10 * 1024 ** 3:
                bomb = True
                break
            try:
                member = tf.next()
            except Exception:  # noqa: BLE001
                break            # усечённый архив: заголовки дальше недоступны
    except Exception:  # noqa: BLE001
        pass
    if bomb:
        out.append(_f("FMT-04", "Tar: чрезмерный суммарный размер (bomb)", "medium", 0.5,
                      f"declared={total_u}", cat="FMT"))
    return out


def _scan_xml(blob: bytes, label: str) -> list[dict]:
    if b"<!DOCTYPE" in blob or b"<!ENTITY" in blob:
        return [_f("FMT-06", f"XML: DOCTYPE/ENTITY (XXE) в {label}", "high", 0.75,
                   "doctype/entity", cat="FMT")]
    return []


def _scan_json_ext(text: str, label: str) -> list[dict]:
    """Дополнительно к JSON: утечки секретов и trust_remote_code."""
    return _scan_secrets(text, label)


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



# Лимиты распаковки в доверенной зоне (docs/14, P0-3): защита от zip-бомб.
MEMBER_LIMIT = 32 * 1024 * 1024
TOTAL_LIMIT = 128 * 1024 * 1024
MEMBER_COUNT_LIMIT = 2000


class _Budget:
    def __init__(self, total=TOTAL_LIMIT):
        self.left = total

    def take(self, n):
        n = max(0, min(int(n), self.left))
        self.left -= n
        return n


def _read_member(zf, info, budget, limit=MEMBER_LIMIT):
    budget = _Budget()
    """Член архива с ограничением по РАЗЖАТОМУ размеру (защита от бомб)."""
    want = min(info.file_size or 0, limit, budget.left)
    if want <= 0:
        return b"", True
    try:
        with zf.open(info) as fh:
            data = fh.read(want + 1)
    except Exception:
        return b"", True
    truncated = len(data) > want
    data = data[:want]
    budget.take(len(data))
    return data, truncated

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
        if ext == ".keras" or any(n.endswith(".weights.h5") for n in names):
            return "keras"      # Keras 3: config.json + metadata.json + *.weights.h5
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
    if ext in (".tar", ".tgz") or path.name.lower().endswith((".tar.gz", ".tar.bz2", ".tar.xz")):
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
    for magic, kind in UNSUPPORTED_MAGIC.items():
        if head.startswith(magic):
            return "unsupported"
    if ext in (".jsonl", ".ndjson"):
        return "jsonl"
    if ext in (".csv", ".tsv"):
        return "csv"
    if ext in (".msgpack", ".mpk"):
        return "msgpack"
    if ext in COMPRESSED_EXT:
        # .tar.gz уже отдан в tar выше; всё остальное — сжатый payload
        return "compressed" if not ext.endswith("tar.gz") else "tar"
    if ext in (".html", ".htm", ".svg"):
        return "html"
    if path.name.lower() in ("dockerfile", "containerfile") or ext == ".dockerfile":
        return "dockerfile"
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


def static_scan(path: Path, total_size: int | None = None) -> dict:
    """Адаптер: вернуть {format, findings, details} для не-pickle форматов.

    total_size — реальный размер исходного объекта, если анализируется префикс
    (потоковый статический анализ больших файлов, P1-6): границы тензоров и
    trailing-данные считаются от него, а не от длины префикса.
    """
    try:
        with path.open("rb") as fh:
            head = fh.read(4096)
    except Exception as exc:  # noqa: BLE001
        return {"format": "unknown", "findings": [], "error": str(exc)}
    if total_size is None:
        try:
            total_size = path.stat().st_size
        except OSError:
            total_size = None
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
            findings.extend(_scan_safetensors(_read_bounded(path), path.name,
                                              total_size or path.stat().st_size))
        elif fmt == "tar":
            findings.extend(_scan_tar(path))
        elif fmt == "xml":
            findings.extend(_scan_xml(_read_bounded(path), path.name))
        elif fmt == "config":
            blob = _read_bounded(path)
            text = _btext(blob)
            findings.extend(_scan_json(text, path.name))
            findings.extend(_scan_secrets(text, path.name))
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
            card_text = _btext(_read_bounded(path))
            findings.extend(_scan_card(card_text, path.name))
            findings.extend(_scan_secrets(card_text, path.name))
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
            findings.extend(_scan_secrets(_btext(_read_bounded(path)), path.name))
            findings.extend(_scan_pmml(_btext(_read_bounded(path)), path.name))
        elif fmt == "savedmodel":
            findings.extend(_scan_savedmodel(_read_bounded(path), path.name))
        elif fmt == "jinja":
            findings.extend(_scan_jinja(_btext(_read_bounded(path)), path.name))
        elif fmt == "jsonl":
            findings.extend(_scan_jsonl(_read_bounded(path), path.name))
        elif fmt == "csv":
            findings.extend(_scan_csv(_read_bounded(path), path.name))
        elif fmt == "msgpack":
            findings.extend(_scan_msgpack(_read_bounded(path), path.name))
        elif fmt == "compressed":
            inner = _decompress(path)
            if inner is None:
                findings.append(_f("FMT-01", f"Не удалось распаковать {path.suffix} ({path.name})",
                                   "low", 0.4, "decompress error", cat="FMT"))
            else:
                import io as _io
                inner_fmt = detect(Path(path.name[:-len(path.suffix)]), inner[:4096])
                if inner[:2] in (b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05") or \
                        inner_fmt in ("pickle", "torch", "joblib", "numpy", "unknown"):
                    findings.extend(_scan_compressed_pickle(inner, path.name))
                elif inner[:4] == b"PK\x03\x04":
                    findings.extend(_scan_nested_archive(inner, path.name))
                else:
                    findings.extend(_scan_python(_btext(inner), path.name))
        elif fmt == "unsupported":
            findings.append(_f("FMT-01", f"Контейнер не поддерживается для разбора ({path.name})",
                               "low", 0.3, "7z/rar/zstd: разбор невозможен", cat="FMT"))
        elif fmt == "html":
            findings.extend(_scan_html(_read_bounded(path), path.name))
        elif fmt == "dockerfile":
            findings.extend(_scan_dockerfile(_btext(_read_bounded(path)), path.name))
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
