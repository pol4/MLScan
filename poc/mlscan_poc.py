#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MLScanner PoC — минимальный анализатор опасности ML-моделей в формате pickle.

Один файл. Реализует три метода проверки:
  1. Статический анализ (без исполнения): pickletools + allowlist/denylist глобалов,
     поиск опасных callable, эвристики, разбор zip-контейнеров.
  2. Динамический анализ в изоляции: запуск десериализации в hardening-контейнере Docker
     с полной наблюдаемостью (Python audit hooks: open/exec/socket/subprocess/ctypes/import),
     без сети, read-only rootfs, drop caps, лимиты cgroup.
  3. Поведенческое тестирование: минимальный probe загруженного объекта (predict/__call__/
     forward) синтетическими входами, фиксация выходов, ошибок, времени и памяти.

Результат — Markdown-отчёт. Поддерживаемые форматы pickle-семейства:
  .pkl/.pickle, .joblib, .dill, .cloudpickle, .pt/.pth/.bin/.ckpt (torch),
  .npy/.npz (object-массивы), а также zip/tar-контейнеры; .h5/.safetensors/.onnx
  детектируются как «не pickle».

Требуется заранее установленный и запущенный Docker (для динамического этапа).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import pickletools
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

VERSION = "0.1.0"

# ----------------------------------------------------------------------------
# Константы / сигнатуры форматов
# ----------------------------------------------------------------------------
MAGIC_NPY = b"\x93NUMPY"
MAGIC_HDF5 = b"\x89HDF\r\n\x1a\n"
MAGIC_ZIP = b"PK\x03\x04"
PICKLE_PROTO_MARKERS = (b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05")

FORMAT_BY_EXT = {
    ".pkl": "pickle", ".pickle": "pickle", ".p": "pickle",
    ".joblib": "joblib", ".jl": "joblib",
    ".dill": "dill", ".cloudpickle": "cloudpickle",
    ".pt": "torch", ".pth": "torch", ".bin": "torch", ".ckpt": "torch",
    ".npy": "numpy", ".npz": "numpy",
    ".h5": "hdf5", ".hdf5": "hdf5",
    ".safetensors": "safetensors",
    ".onnx": "onnx",
    ".zip": "zip", ".tar": "tar", ".gz": "tar", ".tgz": "tar",
}

DANGEROUS_MODULES = {
    "os", "posix", "nt", "subprocess", "shutil", "pty", "platform",
    "socket", "ssl", "sslsocket", "http", "urllib", "urllib2", "urllib3", "requests",
    "ftplib", "telnetlib", "smtplib", "poplib", "imaplib", "socketserver", "xmlrpc",
    "ctypes", "cffi", "mmap", "fcntl", "pwd", "grp", "spwd", "crypt",
    "builtins", "__builtin__", "imp", "importlib", "runpy", "code", "codeop",
    "marshal", "webbrowser", "multiprocessing", "signal", "resource", "getpass",
    "sys", "importlib.machinery", "importlib.util",
}

DANGEROUS_NAMES = {
    "system", "popen", "spawn", "spawnv", "spawnl", "spawnvp", "spawnve",
    "exec", "execv", "execve", "execl", "execlp", "execvp", "execvpe",
    "fork", "forkpty", "call", "check_output", "check_call", "run", "Popen",
    "getoutput", "getstatusoutput", "eval", "compile", "__import__", "open",
    "loads", "load_module", "import_module", "__build_class__",
    "FunctionType", "CodeType", "create_function", "create_code",
    "dlopen", "dlsym", "CDLL", "PyDLL", "WinDLL", "call_function",
    "connect", "connect_ex", "bind", "sendto", "sendall",
    "urlopen", "urlretrieve", "fromfile", "memmap",
}

KNOWN_SAFE_MODULES = {
    "numpy", "numpy.core", "numpy.core.multiarray", "numpy.core.numeric",
    "numpy._core", "numpy._core.multiarray", "numpy._core.numeric",
    "torch", "torch._utils", "torch.storage", "torch.nn", "torch.nn.parameter",
    "torch.serialization", "collections", "sklearn", "scipy", "pandas",
    "joblib", "joblib.numpy_pickle", "copyreg", "_codecs", "operator", "copy",
}

SUSPICIOUS_SUBSTRINGS = {
    b"/bin/sh": "shell", b"/bin/bash": "shell", b"cmd.exe": "shell",
    b"powershell": "shell", b"curl ": "download", b"wget ": "download",
    b"http://": "network", b"https://": "network",
    b"169.254.169.254": "cloud_metadata", b"base64": "obfuscation",
    b"eval(": "eval", b"exec(": "exec", b"__reduce__": "reduce",
    b"socket": "network", b"subprocess": "subprocess", b"os.system": "shell",
}

# ----------------------------------------------------------------------------
# Модель находки
# ----------------------------------------------------------------------------
@dataclass
class Finding:
    check_id: str
    category: str
    title: str
    severity: str
    confidence: float
    evidence: str = ""


# ----------------------------------------------------------------------------
# L1. Статический анализ
# ----------------------------------------------------------------------------
def _as_text(x: Any) -> str:
    if isinstance(x, bytes):
        try:
            return x.decode("utf-8", "replace")
        except Exception:
            return repr(x)
    return str(x)


def disassemble(blob: bytes) -> tuple[list[str], list[str], str | None]:
    """Безопасный разбор pickle-потока в opcodes без исполнения."""
    ops: list[str] = []
    globals_found: list[str] = []
    str_stack: list[str] = []
    error: str | None = None
    try:
        for op, arg, _pos in pickletools.genops(blob):
            ops.append(op.name)
            if op.name in ("GLOBAL", "INST"):
                globals_found.append(_as_text(arg))
            elif op.name == "STACK_GLOBAL":
                if len(str_stack) >= 2:
                    name = str_stack.pop()
                    module = str_stack.pop()
                    globals_found.append(f"{module} {name}")
                else:
                    globals_found.append("<stack-global>")
            elif op.name in (
                "SHORT_BINUNICODE", "BINUNICODE", "UNICODE", "BINUNICODE8",
                "SHORT_BINSTRING", "BINSTRING", "STRING", "BINBYTES",
                "SHORT_BINBYTES", "BINBYTES8", "UNICODE", "BINUNICODE",
            ):
                str_stack.append(_as_text(arg))
    except Exception as exc:  # noqa: BLE001
        error = f"{type(exc).__name__}: {exc}"
    return ops, globals_found, error


def classify_global(g: str) -> tuple[str, str, str]:
    """Возвращает (module, name, класс): dangerous|safe|unknown."""
    g = g.replace(" ", ".")
    if "." in g:
        module, name = g.rsplit(".", 1)
    else:
        module, name = g, g
    if module in DANGEROUS_MODULES or name in DANGEROUS_NAMES:
        return module, name, "dangerous"
    root = module.split(".")[0]
    if module in KNOWN_SAFE_MODULES or root in KNOWN_SAFE_MODULES:
        return module, name, "safe"
    return module, name, "unknown"


def static_scan_pickle(blob: bytes, label: str) -> tuple[list[Finding], list[str], list[str], str | None]:
    findings: list[Finding] = []
    ops, globals_found, err = disassemble(blob)
    if err:
        findings.append(Finding("A-00", "A", f"Некорректный/незавершённый pickle ({label})",
                                "low", 0.4, err))
    if "REDUCE" in ops or "BUILD" in ops:
        findings.append(Finding("A-02", "A",
                                f"Присутствуют REDUCE/BUILD ({label}) — вызовы при десериализации",
                                "medium", 0.6, f"opcodes={[o for o in ops if o in ('REDUCE', 'BUILD')]}"))
    for g in globals_found:
        module, name, kind = classify_global(g)
        if kind == "dangerous":
            findings.append(Finding("A-01", "A",
                                    f"Опасный глобал {g} ({label})",
                                    "critical", 0.9, f"GLOBAL {g}"))
        elif kind == "unknown":
            findings.append(Finding("A-19", "A",
                                    f"Неизвестный глобал {g} ({label})",
                                    "low", 0.5, f"GLOBAL {g}"))
    for pat, tag in SUSPICIOUS_SUBSTRINGS.items():
        if pat in blob:
            findings.append(Finding("A-20", "A",
                                    f"Подозрительная подстрока «{pat.decode('latin1')}» ({tag}) в {label}",
                                    "medium" if tag in ("shell", "subprocess", "exec", "eval",
                                                        "cloud_metadata", "network") else "low",
                                    0.5, tag))
    return findings, ops, globals_found, err


def _npy_payload(blob: bytes) -> bytes:
    if not blob.startswith(MAGIC_NPY) or len(blob) < 10:
        return blob
    major = blob[6]
    if major == 1:
        hlen = int.from_bytes(blob[8:10], "little")
        off = 10
    else:
        hlen = int.from_bytes(blob[8:12], "little")
        off = 12
    return blob[off + hlen:]


def scan_zip_container(path: Path, data: bytes) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    members_scanned: list[str] = []
    try:
        zf = zipfile.ZipFile(path if path.exists() else _bytes_path(data))
    except Exception as exc:  # noqa: BLE001
        findings.append(Finding("B-01", "B", "Не удалось открыть zip-контейнер", "low", 0.3, str(exc)))
        return findings, members_scanned
    for info in zf.infolist():
        name = info.filename
        if name.startswith("/") or ".." in Path(name).parts:
            findings.append(Finding("B-03", "B", f"Подозрительный путь в архиве: {name}",
                                    "high", 0.8, "zip-slip/path traversal"))
        low = name.lower()
        candidate = low.endswith((".pkl", ".pickle", ".joblib", ".pt", ".pth", ".bin", "data.pkl"))
        try:
            head = zf.read(info)[:2] if info.file_size < 200_000_000 else b""
        except Exception:  # noqa: BLE001
            head = b""
        if not candidate and not head.startswith(b"\x80"):
            continue
        try:
            member = zf.read(info)
        except Exception as exc:  # noqa: BLE001
            findings.append(Finding("B-02", "B", f"Не удалось прочитать член {name}", "low", 0.3, str(exc)))
            continue
        sub, _ops, _g, _e = static_scan_pickle(member, name)
        findings.extend(sub)
        members_scanned.append(name)
    return findings, members_scanned


def _bytes_path(data: bytes) -> Any:
    import io
    return io.BytesIO(data)


def detect_format(path: Path) -> str:
    ext = path.suffix.lower()
    fmt = FORMAT_BY_EXT.get(ext, "pickle" if not ext else "unknown")
    head = b""
    try:
        with path.open("rb") as fh:
            head = fh.read(16)
    except Exception:  # noqa: BLE001
        pass
    if head.startswith(MAGIC_NPY):
        return "numpy"
    if head.startswith(MAGIC_HDF5):
        return "hdf5"
    if head.startswith(MAGIC_ZIP) and fmt in ("unknown", "pickle", "torch", "joblib", "numpy"):
        return fmt if fmt != "unknown" else "zip"
    if head[:2] in PICKLE_PROTO_MARKERS and fmt == "unknown":
        return "pickle"
    return fmt


def static_stage(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    fmt = detect_format(path)
    result: dict[str, Any] = {"format": fmt, "size": len(data), "findings": [], "members": []}

    if fmt in ("hdf5", "safetensors", "onnx"):
        result["findings"].append(
            Finding("D-10", "B", f"Формат {fmt} не является pickle; десериализация pickle не применима",
                    "info", 0.9, "binary tensor container").__dict__)
        return result

    if data[:4] == MAGIC_ZIP:
        findings, members = scan_zip_container(path, data)
        result["findings"].extend(f.__dict__ for f in findings)
        result["members"] = members
        if not members:
            result["findings"].append(
                Finding("B-11", "B", "Zip-контейнер без распознанных pickle-членов",
                        "info", 0.5, "нет data.pkl/*.pkl").__dict__)
        return result

    blob = _npy_payload(data) if fmt == "numpy" else data
    findings, ops, globals_found, err = static_scan_pickle(blob, path.name)
    result["findings"].extend(f.__dict__ for f in findings)
    result["opcode_count"] = len(ops)
    result["globals"] = globals_found
    return result


# ----------------------------------------------------------------------------
# L2 + L3. Динамический и поведенческий этапы (гоняются в контейнере)
# ----------------------------------------------------------------------------
HARNESS_SRC = r'''# -*- coding: utf-8 -*-
"""In-container harness: наблюдаемая десериализация + поведенческий probe.

Модель принимается по stdin (никаких расшаренных каталогов), результат — в stdout
строкой с маркером RESULT_MARKER. sys.argv: [0]='-c', [1]=base64-бутстрап (не используется
здесь), [2]=fmt, [3]=имя файла (для корректного выбора загрузчика по расширению).
"""
import io
import json
import os
import shutil
import sys
import tempfile
import time
import zipfile

FMT = sys.argv[2] if len(sys.argv) > 2 else "pickle"
NAME = sys.argv[3] if len(sys.argv) > 3 else "sample.pkl"
RESULT_MARKER = "MLSCAN_RESULT_JSON:"


def recv_target(name):
    """Принимает модель из stdin и сохраняет её в tmpfs-каталог контейнера."""
    d = tempfile.mkdtemp(prefix="mlscan-in-", dir="/tmp")
    path = os.path.join(d, os.path.basename(name) or "sample.pkl")
    with open(path, "wb") as fh:
        shutil.copyfileobj(sys.stdin.buffer, fh, 1 << 20)
    return path

phase = ["setup"]
_record = True
events = []
MAX_EVENTS = 5000

INTERESTING = {
    "open", "os.system", "os.exec", "os.spawn", "os.posix_spawn", "subprocess.Popen",
    "socket.connect", "socket.connect_ex", "socket.bind", "socket.getaddrinfo",
    "socket.gethostbyname", "socket.gethostbyaddr", "socket.sendto", "socket.__new__",
    "ctypes.dlopen", "ctypes.dlsym", "ctypes.call_function",
    "import", "exec", "compile", "marshal.load", "marshal.loads",
    "runpy.run_module", "runpy.run_path", "os.chdir",
    "os.mkdir", "os.remove", "os.rename", "os.link", "os.symlink",
    "shutil.copyfile", "shutil.copytree", "shutil.move",
    "urllib.Request", "ftplib.connect", "smtplib.connect",
}


def _short(x, n=300):
    try:
        s = repr(x)
    except Exception:
        s = "<unrepr>"
    return s if len(s) <= n else s[:n] + ("...<%d>" % len(s))


LIB_PREFIXES = tuple(p for p in (getattr(sys, "prefix", ""), getattr(sys, "base_prefix", "")) if p)


def _is_lib_code(filename):
    """Отличает код библиотек/импорт-машины от кода полезной нагрузки."""
    try:
        fn = str(filename or "")
    except Exception:
        return True
    if fn.startswith("<"):
        return fn not in ("<string>", "<stdin>")
    if "site-packages" in fn or "dist-packages" in fn:
        return True
    return any(p and fn.startswith(p) for p in LIB_PREFIXES)


def _norm(event, args):
    """Нормализация аргументов: убираем шум, оставляем значимое."""
    try:
        if event == "open":
            return [_short(args[0], 200), _short(args[1], 16)]
        if event == "import":
            return [_short(args[0], 120), _short(args[1], 120)]
        if event in ("exec", "compile"):
            return [_short(args[0], 160)]
        return [_short(a, 200) for a in args]
    except Exception:
        return ["<norm-error>"]


def hook(event, args):
    if not _record or event not in INTERESTING or len(events) >= MAX_EVENTS:
        return
    try:
        if event == "exec":
            co = args[0] if args else None
            if co is None or _is_lib_code(getattr(co, "co_filename", "")):
                return
        elif event == "compile":
            if len(args) > 1 and _is_lib_code(args[1]):
                return
        elif event == "marshal.loads":
            return  # шум загрузчика .pyc
        events.append({"t": round(time.monotonic(), 4), "phase": phase[0],
                       "event": event, "args": _norm(event, args)})
    except Exception:
        pass



def unpickle_bytes(data, errors):
    import pickle
    try:
        return pickle.loads(data, fix_imports=False, encoding="latin1")
    except Exception as e:
        errors.append("pickle.loads: %s: %s" % (type(e).__name__, e))
    try:
        class Probe(pickle.Unpickler):
            def find_class(self, module, name):
                try:
                    import importlib
                    return getattr(importlib.import_module(module), name)
                except Exception as e:
                    raise RuntimeError("find_class %s.%s: %s" % (module, name, e))
        return Probe(io.BytesIO(data)).load()
    except Exception as e:
        errors.append("probe.load: %s: %s" % (type(e).__name__, e))
    return None


def load_zip(data, errors):
    objs = []
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception as e:
        errors.append("zip: %s: %s" % (type(e).__name__, e))
        return None
    for name in zf.namelist():
        low = name.lower()
        try:
            member = zf.read(name)
        except Exception as e:
            errors.append("member %s: %s" % (name, e))
            continue
        if not (low.endswith((".pkl", ".pickle", ".joblib", ".pt")) or member[:2] == b"\x80"):
            continue
        objs.append({"member": name, "value": unpickle_bytes(member, errors)})
    return objs or None


def npy_payload(data):
    if not data.startswith(b"\x93NUMPY") or len(data) < 10:
        return data
    if data[6] == 1:
        off = 10 + int.from_bytes(data[8:10], "little")
    else:
        off = 12 + int.from_bytes(data[8:12], "little")
    return data[off:]


def load_target(path, fmt, errors):
    data = open(path, "rb").read()
    is_zip = data[:4] == b"PK\x03\x04"

    if fmt == "dill":
        try:
            import dill
            return dill.loads(data)
        except ImportError:
            errors.append("dill не установлен")
        except Exception as e:
            errors.append("dill: %s: %s" % (type(e).__name__, e))
    if fmt == "cloudpickle":
        try:
            import cloudpickle
            return cloudpickle.loads(data)
        except ImportError:
            errors.append("cloudpickle не установлен")
        except Exception as e:
            errors.append("cloudpickle: %s: %s" % (type(e).__name__, e))
    if fmt == "joblib":
        try:
            import joblib
            return joblib.load(path)
        except ImportError:
            errors.append("joblib не установлен")
        except Exception as e:
            errors.append("joblib: %s: %s" % (type(e).__name__, e))
    if fmt == "torch":
        try:
            import torch
            try:
                return torch.load(path, weights_only=False)
            except TypeError:
                return torch.load(path)
        except ImportError:
            errors.append("torch не установлен")
        except Exception as e:
            errors.append("torch: %s: %s" % (type(e).__name__, e))
    if fmt == "numpy":
        try:
            import numpy as np
            obj = np.load(path, allow_pickle=True)
            if getattr(obj, "shape", None) == () and getattr(obj, "dtype", None) == object:
                return obj.item()
            return obj
        except ImportError:
            errors.append("numpy не установлен")
        except Exception as e:
            errors.append("numpy: %s: %s" % (type(e).__name__, e))
        data = npy_payload(data)
    if fmt in ("hdf5", "safetensors", "onnx"):
        errors.append("формат %s не является pickle; динамика не применима" % fmt)
        return None
    if is_zip:
        return load_zip(data, errors)
    return unpickle_bytes(data, errors)


def make_inputs():
    inputs = []
    try:
        import numpy as np
        inputs.append(np.zeros((1, 4), dtype="float32"))
        inputs.append(np.zeros((1, 3, 8, 8), dtype="float32"))
    except Exception:
        pass
    inputs.append([0.0, 0.0, 0.0, 0.0])
    inputs.append("hello world")
    return inputs


SUSPECT_STRINGS = ("exec(", "eval(", "system(", "popen", "subprocess", "socket", "http://",
                   "https://", "base64", "__import__", "urlopen", "os.system", "/etc/",
                   "curl ", "wget ", "chmod ", "powershell", "rm -rf", "marshal")


def snapshot():
    """Снимок критичного состояния процесса до/после операций."""
    import builtins
    s = {"builtins": {}, "modules": set(), "syspath": list(sys.path),
         "env": dict(os.environ), "cwd": None, "meta_path": [], "path_hooks": []}
    try:
        for k, v in vars(builtins).items():
            s["builtins"][k] = id(v)
    except Exception:
        pass
    try:
        s["modules"] = set(sys.modules.keys())
    except Exception:
        pass
    try:
        s["cwd"] = os.getcwd()
    except Exception:
        pass
    try:
        s["meta_path"] = [getattr(x, "__module__", "?") + "." + getattr(x, "__name__", type(x).__name__)
                          for x in sys.meta_path]
    except Exception:
        pass
    try:
        s["path_hooks"] = [getattr(h, "__module__", "?") + "." + getattr(h, "__name__", type(h).__name__)
                           for h in sys.path_hooks]
    except Exception:
        pass
    return s


def diff_snapshot(a, b):
    """Разница снимков: модификация builtins, импорт-хуков, sys.path, окружения, cwd."""
    d = {}
    changed = sorted(k for k, v in b["builtins"].items()
                     if k in a["builtins"] and a["builtins"][k] != v)
    added = sorted(k for k in b["builtins"] if k not in a["builtins"])
    removed = sorted(k for k in a["builtins"] if k not in b["builtins"])
    if changed:
        d["builtins_changed"] = changed
    if added:
        d["builtins_added"] = added
    if removed:
        d["builtins_removed"] = removed
    std = getattr(sys, "stdlib_module_names", set())
    mods = sorted(m for m in (set(b["modules"]) - set(a["modules"]))
                  if m.split(".")[0] not in std)
    if mods:
        d["modules_added"] = mods[:50]
    if a["env"] != b["env"]:
        keys = sorted(set(a["env"]) ^ set(b["env"]))
        keys += sorted(k for k in set(a["env"]) & set(b["env"]) if a["env"][k] != b["env"][k])
        d["env_changed"] = keys
    if a["cwd"] != b["cwd"]:
        d["cwd_changed"] = [a["cwd"], b["cwd"]]
    if a["syspath"] != b["syspath"]:
        d["syspath_changed"] = True
    if a["meta_path"] != b["meta_path"]:
        d["meta_path_changed"] = [a["meta_path"], b["meta_path"]]
    if a["path_hooks"] != b["path_hooks"]:
        d["path_hooks_changed"] = True
    return d


def introspect(obj, max_items=200, max_depth=3):
    """Ограниченный обход объекта: найденные callable и подозрительные строки."""
    callables, suspicious, types = [], [], {}
    seen = set()

    def walk(o, path, depth):
        if len(seen) > max_items or depth > max_depth:
            return
        t = type(o).__name__
        types[t] = types.get(t, 0) + 1
        if t == "ndarray":
            try:
                if getattr(o, "dtype", None) == object:
                    for i, v in enumerate(list(o.ravel())[:max_items]):
                        walk(v, "%s[%d]" % (path, i), depth + 1)
            except Exception:
                pass
            return
        if isinstance(o, (str, bytes)):
            s = o.decode("latin1") if isinstance(o, bytes) else o
            low = s.lower()
            for pat in SUSPECT_STRINGS:
                if pat in low and len(s) < 4000:
                    suspicious.append({"path": path, "pattern": pat, "preview": s[:160]})
                    break
            return
        if callable(o) and not isinstance(o, type):
            callables.append({"path": path, "name": getattr(o, "__name__", t)})
            return
        if id(o) in seen:
            return
        seen.add(id(o))
        if isinstance(o, dict):
            for k, v in list(o.items())[:max_items]:
                walk(v, "%s[%r]" % (path, k), depth + 1)
        elif isinstance(o, (list, tuple, set, frozenset)):
            for i, v in enumerate(list(o)[:max_items]):
                walk(v, "%s[%d]" % (path, i), depth + 1)
        elif getattr(type(o), "__module__", "builtins") != "builtins":
            try:
                for name in dir(o):
                    if name.startswith("__") and name not in ("__call__", "__reduce__", "__reduce_ex__"):
                        continue
                    try:
                        v = getattr(o, name)
                    except Exception:
                        continue
                    if callable(v) and not isinstance(v, type):
                        callables.append({"path": "%s.%s" % (path, name),
                                          "name": getattr(v, "__name__", name)})
            except Exception:
                pass

    if obj is not None:
        walk(obj, "obj", 0)
    return callables, suspicious, types


def behavior_findings(state_load, state_probe, suspicious, summary=None, events=None):
    """Наблюдённые эффекты и изменения состояния → поведенческие находки (L3)."""
    f = []
    summary = summary or {}
    events = events or []

    def add(cid, title, sev, conf, ev):
        f.append({"check_id": cid, "category": "F", "title": title,
                  "severity": sev, "confidence": conf, "evidence": ev})

    def ev_of(pred, limit=3):
        out = []
        for e in events:
            if pred(e["event"]):
                out.append(e["event"] + "(" + ", ".join(e.get("args") or [])[:120] + ")")
            if len(out) >= limit:
                break
        return "; ".join(out) or "-"

    # 1) Эффекты, наблюдаемые при загрузке/выполнении (интерпретация трассы).
    if summary.get("subprocess"):
        add("F-30", f"Запуск внешних процессов/команд при загрузке (×{summary['subprocess']})",
            "high", 0.8, ev_of(lambda n: n in ("os.system", "os.exec", "os.spawn",
                                               "os.posix_spawn", "subprocess.Popen")))
    if summary.get("network_attempts"):
        add("F-31", f"Сетевые обращения при загрузке (×{summary['network_attempts']})",
            "high", 0.75, ev_of(lambda n: n.startswith("socket.")
                                or n in ("ftplib.connect", "smtplib.connect", "urllib.Request")))
    if summary.get("mem_exec"):
        add("F-32", f"Исполнение кода в памяти (exec) при загрузке (×{summary['mem_exec']})",
            "high", 0.8, "exec с code <string>/<stdin>")
    if summary.get("file_writes"):
        add("F-33", f"Запись файлов при загрузке (×{summary['file_writes']})",
            "medium", 0.6, "open(..., 'w/a/x')")

    # 2) Изменения состояния процесса (tampering).
    touched = (state_load.get("builtins_changed") or []) + (state_load.get("builtins_added") or [])
    if touched:
        add("F-20", "Модификация builtins при загрузке: " + ", ".join(touched[:10]), "high", 0.85,
            "builtins changed/added: %s" % touched[:10])
    if state_load.get("builtins_removed"):
        add("F-21", "Удалены элементы builtins: " + ", ".join(state_load["builtins_removed"][:10]),
            "high", 0.8, "builtins removed")
    if state_load.get("meta_path_changed") or state_load.get("path_hooks_changed"):
        add("F-22", "Подмена механизма импорта (sys.meta_path/path_hooks)", "high", 0.8,
            "import hook override")
    if state_load.get("syspath_changed"):
        add("F-23", "Изменён sys.path при загрузке", "medium", 0.6, "sys.path changed")
    if state_load.get("env_changed"):
        add("F-24", "Изменено окружение процесса: " + ", ".join(state_load["env_changed"][:10]),
            "medium", 0.6, "env changed")
    if state_load.get("cwd_changed"):
        add("F-25", "Изменён рабочий каталог", "low", 0.5, "cwd changed")
    if state_probe.get("builtins_changed") or state_probe.get("builtins_added"):
        add("F-26", "Модификация builtins во время вызова модели", "high", 0.8,
            "builtins changed in probe")

    # 3) Содержимое загруженного объекта.
    if suspicious:
        add("F-27", "Подозрительные строки в загруженном объекте: " +
            ", ".join(sorted({s["pattern"] for s in suspicious})), "medium", 0.55,
            "; ".join(s["path"] + ":" + s["pattern"] for s in suspicious[:5]))
    return f


def behavior_probe(obj):
    res = {"callables": [], "results": [], "object": None, "types": {},
           "suspicious_strings": [], "callable_paths": []}
    if obj is None:
        res["object"] = {"type": "NoneType", "repr": "None"}
        return res
    res["object"] = {"type": type(obj).__name__, "repr": _short(obj, 240)}
    callables, suspicious, types = introspect(obj)
    res["suspicious_strings"] = suspicious
    res["types"] = types
    res["callable_paths"] = [c["path"] for c in callables[:20]]

    targets, seen = [], set()
    for name in ("predict", "__call__", "forward", "transform", "generate"):
        if name == "__call__":
            if callable(obj):
                targets.append((name, obj))
        elif hasattr(obj, name) and callable(getattr(obj, name)):
            targets.append((name, getattr(obj, name)))
    uniq = []
    for n, f in targets:
        if id(f) in seen:
            continue
        seen.add(id(f))
        uniq.append((n, f))
    res["callables"] = [n for n, _ in uniq]
    for n, f in uniq:
        for inp in make_inputs():
            t0 = time.monotonic()
            try:
                out = f(inp)
                res["results"].append({"callable": n, "input": type(inp).__name__, "ok": True,
                                       "out_type": type(out).__name__, "preview": _short(out, 200),
                                       "time_ms": round((time.monotonic() - t0) * 1000, 3)})
            except Exception as e:
                res["results"].append({"callable": n, "input": type(inp).__name__, "ok": False,
                                       "error": "%s: %s" % (type(e).__name__, e),
                                       "time_ms": round((time.monotonic() - t0) * 1000, 3)})
    return res


def prewarm(fmt):
    """Прогрев библиотек ДО установки audit-hook: шум импорта не приписывается payload."""
    mods = {"numpy": ["numpy"], "torch": ["torch"], "joblib": ["joblib"],
            "dill": ["dill"], "cloudpickle": ["cloudpickle"]}.get(fmt, [])
    for m in mods:
        try:
            __import__(m)
        except Exception:
            pass


def summarize(events):
    s = {"network_attempts": 0, "subprocess": 0, "exec": 0, "mem_exec": 0,
         "file_writes": 0, "imports": [], "dlopen": 0}
    for e in events:
        ev = e["event"]
        args = e.get("args", [])
        if ev.startswith("socket.") or ev in ("ftplib.connect", "smtplib.connect", "urllib.Request"):
            s["network_attempts"] += 1
        if ev in ("os.system", "os.exec", "os.spawn", "os.posix_spawn", "subprocess.Popen"):
            s["subprocess"] += 1
        if ev in ("exec", "compile"):
            s["exec"] += 1
            a0 = args[0] if args else ""
            # Учитываем только исполнение в фазе загрузки (payload); в фазе probe
            # код <string> может генерироваться ленивым импортом библиотек (numpy и т.п.).
            if e.get("phase") == "load" and ("<string>" in a0 or "<stdin>" in a0):
                s["mem_exec"] += 1
        if ev == "open":
            mode = args[1] if len(args) > 1 else ""
            if any(c in mode for c in "wax+"):
                s["file_writes"] += 1
        if ev == "import":
            s["imports"].append(args[0] if args else "?")
        if ev == "ctypes.dlopen" and (not args or args[0] != "None"):
            s["dlopen"] += 1
    s["imports"] = sorted(set(s["imports"]))
    return s


def main():
    import resource
    info = {"format": FMT, "load": {"ok": False, "type": None, "errors": []},
            "behavior": None, "events": [], "summary": {}, "maxrss_kb": None}
    errors = info["load"]["errors"]
    try:
        rss0 = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    except Exception:
        rss0 = 0
    phase[0] = "warmup"
    prewarm(FMT)
    target = recv_target(NAME)   # приём модели из stdin (до установки хука)
    snap0 = snapshot()
    sys.addaudithook(hook)
    phase[0] = "load"
    t0 = time.monotonic()
    obj = None
    try:
        obj = load_target(target, FMT, errors)
        info["load"]["ok"] = True
        info["load"]["type"] = type(obj).__name__
    except Exception as e:
        errors.append("load: %s: %s" % (type(e).__name__, e))
    info["load"]["time_s"] = round(time.monotonic() - t0, 4)
    snap1 = snapshot()
    state_load = diff_snapshot(snap0, snap1)
    phase[0] = "probe"
    try:
        info["behavior"] = behavior_probe(obj)
    except Exception as e:
        errors.append("behavior: %s" % e)
        info["behavior"] = {"callables": [], "results": [], "object": None,
                            "types": {}, "suspicious_strings": [], "callable_paths": []}
    snap2 = snapshot()
    state_probe = diff_snapshot(snap1, snap2)
    info["summary"] = summarize(events)
    beh = info["behavior"]
    beh["state_changes"] = {"load": state_load, "probe": state_probe}
    beh["findings"] = behavior_findings(state_load, state_probe,
                                        beh.get("suspicious_strings") or [],
                                        info["summary"], events)
    phase[0] = "done"
    global _record
    _record = False
    try:
        rss1 = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    except Exception:
        rss1 = 0
    info["maxrss_kb"] = max(rss0, rss1)
    info["events"] = events
    sys.stdout.write(RESULT_MARKER + json.dumps(info, ensure_ascii=False) + "\n")
    sys.stdout.flush()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        sys.stderr.write("HARNESS_FATAL: %s\n" % exc)
        raise
'''


def docker_available() -> tuple[bool, str]:
    try:
        p = subprocess.run(["docker", "version", "--format", "{{.Server.Version}}"],
                           capture_output=True, text=True, timeout=20)
        if p.returncode == 0 and p.stdout.strip():
            return True, p.stdout.strip()
        return False, (p.stderr or "docker daemon недоступен").strip()
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def dynamic_stage(path: Path, fmt: str, *, image: str, runtime: str | None,
                  timeout: int) -> dict[str, Any]:
    ok, info = docker_available()
    if not ok:
        return {"status": "skipped", "reason": f"docker недоступен: {info}"}

    # Harness передаётся base64-бутстрапом в `python -c` (без монтирования файлов),
    # модель подаётся на stdin контейнера (docker run -i), результат возвращается в stdout.
    b64 = base64.b64encode(HARNESS_SRC.encode("utf-8")).decode("ascii")
    bootstrap = ("import base64,sys;"
                 "exec(compile(base64.b64decode(sys.argv[1]),'<harness>','exec'))")

    # Размер tmpfs под копию модели в контейнере (модель пишется в /tmp).
    try:
        fsize = path.stat().st_size
    except OSError:
        fsize = 0
    tmpfs_mb = max(128, (fsize * 2) // (1024 * 1024) + 64)

    name = f"mlscan-poc-{os.getpid()}-{int(time.time())}"
    cmd = [
        "docker", "run", "--rm", f"--name={name}",
        "--interactive",
        "--network", "none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit=128",
        "--memory=1g", "--memory-swap=1g",
        "--cpus=1",
        "--tmpfs", f"/tmp:rw,nosuid,nodev,size={tmpfs_mb}m",
    ]
    if runtime:
        cmd += ["--runtime", runtime]
    cmd += [
        image,
        "python", "-X", "utf8", "-B", "-c", bootstrap, b64, fmt, path.name,
    ]

    started = time.monotonic()
    result: dict[str, Any]
    timed_out = False
    try:
        with open(path, "rb") as fh:
            proc = subprocess.run(cmd, stdin=fh, capture_output=True, text=True,
                                  timeout=timeout)
        rc, stdout, stderr = proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as exc:
        subprocess.run(["docker", "kill", name], capture_output=True)
        rc, stdout, stderr, timed_out = -1, "", str(exc), True
    except Exception as exc:  # noqa: BLE001
        return {"status": "error", "reason": f"не удалось запустить контейнер: {exc}"}

    wall = round(time.monotonic() - started, 3)
    result = {"status": "ok", "wall_s": wall, "exit_code": rc,
              "timed_out": timed_out,
              "stdout": (stdout or "")[-4000:], "stderr": (stderr or "")[-4000:]}

    payload = None
    for line in (stdout or "").splitlines():
        if line.startswith("MLSCAN_RESULT_JSON:"):
            payload = line[len("MLSCAN_RESULT_JSON:"):]
    if payload is not None:
        try:
            result.update(json.loads(payload))
        except Exception as exc:  # noqa: BLE001
            result["parse_error"] = str(exc)
    else:
        result["status"] = "no-result"
    return result


# ----------------------------------------------------------------------------
# Сведение результатов и вердикт
# ----------------------------------------------------------------------------
SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def decide(static: dict[str, Any], dynamic: dict[str, Any]) -> tuple[str, str]:
    sevs = [f["severity"] for f in static.get("findings", [])]
    max_sev = max(sevs, key=lambda s: SEV_RANK.get(s, 0)) if sevs else "info"

    dyn_reasons = []
    if dynamic.get("status") == "skipped":
        dyn_reasons.append("динамика не выполнена (нет Docker)")
    s = dynamic.get("summary") or {}
    beh_findings = ((dynamic.get("behavior") or {}).get("findings")) or []
    beh_sev = max((f.get("severity") for f in beh_findings),
                  key=lambda x: SEV_RANK.get(x, 0), default="info")
    if SEV_RANK.get(beh_sev, 0) > SEV_RANK.get(max_sev, 0):
        max_sev = beh_sev
    if s.get("network_attempts"):
        dyn_reasons.append(f"попытки сетевого доступа: {s['network_attempts']}")
    if s.get("subprocess"):
        dyn_reasons.append(f"запуск процессов/команд: {s['subprocess']}")
    if s.get("mem_exec"):
        dyn_reasons.append(f"исполнение кода в памяти (exec <string>): {s['mem_exec']}")
    if s.get("dlopen"):
        dyn_reasons.append(f"загрузка нативных библиотек (ctypes): {s['dlopen']}")
    if s.get("file_writes"):
        dyn_reasons.append(f"запись файлов: {s['file_writes']}")
    if beh_findings:
        dyn_reasons.append("поведенческие находки: " +
                           ", ".join(f["check_id"] for f in beh_findings[:6]))
    if dynamic.get("timed_out"):
        dyn_reasons.append("превышен таймаут (возможный DoS/бесконечный цикл)")

    hard_dynamic = bool(s.get("network_attempts") or s.get("subprocess")
                        or s.get("mem_exec") or s.get("dlopen") or s.get("file_writes")
                        or dynamic.get("timed_out"))

    if max_sev in ("critical", "high") and hard_dynamic:
        return "Malicious", f"Максимальная серьёзность {max_sev}; динамика: " + "; ".join(dyn_reasons)
    if max_sev in ("critical", "high"):
        return "Dangerous", f"Находки уровня {max_sev} без подтверждения динамикой: " + \
            "; ".join(dyn_reasons or ["требуется подтверждение динамикой"])
    if hard_dynamic:
        return "Dangerous", "Динамика: " + "; ".join(dyn_reasons)
    if dynamic.get("status") == "skipped":
        return "Inconclusive", "Только статика: динамика недоступна; неполное покрытие"
    if max_sev == "medium":
        return "Needs review", "Находки среднего уровня"
    return "Safe", "Опасных признаков не обнаружено"


def render_report(path: Path, sha: str, static: dict[str, Any],
                  dynamic: dict[str, Any], verdict: str, reason: str) -> str:
    L: list[str] = []
    L.append("# Отчёт MLScanner PoC")
    L.append("")
    L.append(f"- **Артефакт:** `{path.name}`")
    L.append(f"- **Размер:** {static.get('size', 0)} байт")
    L.append(f"- **SHA-256:** `{sha}`")
    L.append(f"- **Формат:** `{static.get('format')}`")
    L.append(f"- **Вердикт:** **{verdict}** — {reason}")
    L.append(f"- **Дата:** {time.strftime('%Y-%m-%d %H:%M:%S')}")
    L.append("")
    L.append("## 1. Статический анализ (L1)")
    findings = static.get("findings", [])
    if static.get("members"):
        L.append(f"Просканированные члены контейнера: {', '.join(static['members'])}")
        L.append("")
    if not findings:
        L.append("Находок нет.")
    else:
        L.append("| ID | Кат. | Severity | Уверенность | Находка | Доказательство |")
        L.append("|----|------|----------|-------------|---------|----------------|")
        for f in sorted(findings, key=lambda x: -SEV_RANK.get(x["severity"], 0)):
            L.append("| {id} | {cat} | {sev} | {conf:.2f} | {title} | `{ev}` |".format(
                id=f["check_id"], cat=f["category"], sev=f["severity"],
                conf=f["confidence"], title=f["title"],
                ev=(f.get("evidence") or "").replace("|", "\\|")[:200]))
    L.append("")
    L.append("## 2. Динамический анализ в песочнице (L2)")
    if dynamic.get("status") == "skipped":
        L.append(f"Пропущен: {dynamic.get('reason')}")
    else:
        L.append(f"- Статус: `{dynamic.get('status')}`, exit code: `{dynamic.get('exit_code')}`, "
                 f"wall: {dynamic.get('wall_s')} с")
        load = dynamic.get("load") or {}
        L.append(f"- Загрузка: ok=`{load.get('ok')}`, тип=`{load.get('type')}`, "
                 f"время={load.get('time_s')} с")
        for e in (load.get("errors") or [])[:10]:
            L.append(f"  - ошибка загрузки: `{e}`")
        s = dynamic.get("summary") or {}
        L.append(f"- Сеть: {s.get('network_attempts', 0)}, процессы: {s.get('subprocess', 0)}, "
                 f"exec: {s.get('exec', 0)} (в памяти: {s.get('mem_exec', 0)}), "
                 f"dlopen: {s.get('dlopen', 0)}, запись файлов: {s.get('file_writes', 0)}, "
                 f"maxRSS: {dynamic.get('maxrss_kb', '?')} КБ")
        evs = dynamic.get("events") or []
        if evs:
            L.append("")
            L.append("Наблюдаемые события (первые 40):")
            L.append("")
            L.append("| t | phase | event | args |")
            L.append("|---|-------|-------|------|")
            for e in evs[:40]:
                args = ", ".join(e.get("args", []))[:180].replace("|", "\\|")
                L.append(f"| {e['t']} | {e['phase']} | {e['event']} | `{args}` |")
        if dynamic.get("stderr"):
            L.append("")
            L.append("<details><summary>stderr контейнера</summary>")
            L.append("")
            L.append("```")
            L.append(dynamic["stderr"][-2000:])
            L.append("```")
            L.append("</details>")
    L.append("")
    L.append("## 3. Поведенческое тестирование (L3)")
    beh = dynamic.get("behavior") if dynamic.get("status") != "skipped" else None
    if not beh:
        L.append("Пропущено (модель не загружена вне песочницы).")
    else:
        bf = beh.get("findings") or []
        if bf:
            L.append("Находки по поведению:")
            L.append("")
            L.append("| ID | Severity | Находка | Доказательство |")
            L.append("|----|----------|---------|----------------|")
            for f in bf:
                ev = (f.get("evidence") or "").replace("|", "\\|")[:160]
                L.append(f"| {f['check_id']} | {f['severity']} | "
                         f"{f['title'].replace('|', chr(92) + '|')} | `{ev}` |")
            L.append("")
        else:
            L.append("Признаков опасного поведения не обнаружено.")
        sc = beh.get("state_changes") or {}
        if sc.get("load"):
            L.append(f"- Изменения состояния при загрузке: `{json.dumps(sc['load'], ensure_ascii=False)[:400]}`")
        if sc.get("probe"):
            L.append(f"- Изменения состояния при probe: `{json.dumps(sc['probe'], ensure_ascii=False)[:300]}`")
        obj = beh.get("object")
        if obj:
            L.append(f"- Загруженный объект: тип `{obj.get('type')}`, `{obj.get('repr')}`")
        L.append(f"- Обнаруженные callable: {', '.join(beh.get('callables') or []) or '—'}")
        paths = beh.get("callable_paths") or []
        if paths:
            L.append(f"- Callable внутри объекта: {', '.join(paths[:10])}")
        ss = beh.get("suspicious_strings") or []
        if ss:
            L.append(f"- Подозрительные строки: " +
                     "; ".join(f"{x['path']} ≈ {x['pattern']}" for x in ss[:5]))
        L.append("")
        res = beh.get("results") or []
        if res:
            L.append("| callable | input | ok | результат | время, мс |")
            L.append("|----------|-------|----|-----------|-----------|")
            for r in res[:30]:
                out = r.get("preview") or r.get("error") or ""
                out = out[:120].replace("|", "\\|")
                L.append(f"| {r['callable']} | {r['input']} | {r['ok']} | `{out}` | {r.get('time_ms')} |")
        else:
            L.append("Вызовы модели не обнаружены (payload действует на этапе загрузки).")
    L.append("")
    L.append("## Ограничения PoC")
    L.append("- Наблюдаемость на уровне Python audit hooks + изоляции Docker "
             "(не eBPF и не микро-ВМ); при необходимости — `--runtime runsc` (gVisor).")
    L.append("- Вредоносный payload может уклоняться от песочницы (sandbox evasion).")
    L.append("- Отсутствие находок при пропущенной динамике трактуется как Inconclusive.")
    L.append("")
    return "\n".join(L)


# ----------------------------------------------------------------------------
# Оркестрация
# ----------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="MLScanner PoC — анализ опасности pickle-моделей")
    ap.add_argument("target", help="путь к файлу модели (или '-' для чтения из stdin)")
    ap.add_argument("--out", default=None, help="файл отчёта Markdown (по умолчанию stdout)")
    ap.add_argument("--image", default="python:3.11-slim", help="образ Docker для песочницы")
    ap.add_argument("--runtime", default=None, help="runtime Docker, напр. runsc (gVisor)")
    ap.add_argument("--timeout", type=int, default=60, help="таймаут этапа динамики, с")
    ap.add_argument("--static-only", action="store_true", help="без запуска контейнера")
    ap.add_argument("--name", default=None,
                    help="имя/расширение при вводе из stdin ('-'): напр. model.pt")
    ap.add_argument("--keep", action="store_true",
                    help="сохранить временный файл при вводе из stdin")
    ap.add_argument("--version", action="version", version=VERSION)
    args = ap.parse_args()

    cleanup: Path | None = None
    if args.target == "-":
        name = args.name or "sample.pkl"
        tdir = Path(tempfile.mkdtemp(prefix="mlscan-in-"))
        path = tdir / Path(name).name
        with path.open("wb") as fh:
            shutil.copyfileobj(sys.stdin.buffer, fh)
        if not args.keep:
            cleanup = tdir
    else:
        path = Path(args.target)

    if not path.is_file():
        print(f"Ошибка: файл не найден: {path}", file=sys.stderr)
        return 2

    try:
        sha = hashlib.sha256(path.read_bytes()).hexdigest()
        static = static_stage(path)

        if args.static_only:
            dynamic: dict[str, Any] = {"status": "skipped",
                                       "reason": "запрошен режим --static-only"}
        else:
            dynamic = dynamic_stage(path, static["format"], image=args.image,
                                    runtime=args.runtime, timeout=args.timeout)

        verdict, reason = decide(static, dynamic)
        report = render_report(path, sha, static, dynamic, verdict, reason)
    finally:
        if cleanup is not None:
            shutil.rmtree(cleanup, ignore_errors=True)

    if args.out:
        Path(args.out).write_text(report, encoding="utf-8")
        print(f"Отчёт записан: {args.out}")
    else:
        print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
