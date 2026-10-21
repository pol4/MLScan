#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Прогон синтетического корпуса через развёрнутую систему MLScan и отчёт о детекции.

Использование:
  python run_tests.py --url http://127.0.0.1:18080 --analytics-url http://127.0.0.1:18081 \
      --key <API_KEY> [--out REPORT.md] [--timeout 180]

Для каждого образца: POST /scans/upload (с ключом) -> ожидание state=done -> сбор находок;
затем POST /sync в аналитику и чтение policy-вердикта. Результат — таблица «обнаружено/нет».

fmt выбирается по расширению (pickle/joblib/dill/cloudpickle/numpy/torch/raw).
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLES = os.path.join(HERE, "samples")
EXPECTED = os.path.join(HERE, "expected.json")

FMT_BY_EXT = {"pkl": "pickle", "pickle": "pickle", "p": "pickle",
              "joblib": "joblib", "jl": "joblib", "dill": "dill",
              "cloudpickle": "cloudpickle", "npy": "numpy", "npz": "numpy",
              "pt": "torch", "pth": "torch", "bin": "torch", "ckpt": "torch",
              # сложные форматы (проверяются и статикой, и динамикой в песочнице)
              "safetensors": "safetensors", "onnx": "onnx", "h5": "hdf5", "hdf5": "hdf5",
              "keras": "keras", "gguf": "gguf", "zip": "zip", "tar": "tar", "gz": "tar",
              "tgz": "tar", "xml": "xml", "yaml": "config", "yml": "config",
              "md": "card", "png": "image", "jpg": "image",
              # «Волна 4»: ноутбуки, скрипты, MLflow/SavedModel/TFLite/CoreML/PMML, датасеты
              "ipynb": "notebook", "sh": "script", "bash": "script", "ps1": "script",
              "tflite": "tflite", "mlmodel": "coreml", "pmml": "pmml",
              "parquet": "dataset", "arrow": "dataset", "feather": "dataset",
              # «Волна 5»: wheel/.pth, нативные библиотеки, Jinja, H5/Keras, frozen .pb
              "whl": "zip", "pth": "torch", "so": "native", "dll": "native",
              "j2": "jinja", "jinja": "jinja", "pb": "savedmodel"}


_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def req(url: str, key: str, data: bytes | None = None, method: str = "GET"):
    r = urllib.request.Request(url, data=data, method=method,
                               headers={"Authorization": f"Bearer {key}"})
    with _OPENER.open(r, timeout=60) as resp:
        return json.loads(resp.read().decode())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--analytics-url", default="")
    ap.add_argument("--key", required=True)
    ap.add_argument("--out", default=os.path.join(HERE, "REPORT.md"))
    ap.add_argument("--timeout", type=int, default=180)
    args = ap.parse_args()
    base = args.url.rstrip("/")

    expected = json.load(open(EXPECTED))
    rows, detected_n, missed_n, fp_n = [], 0, 0, 0
    for name, exp in sorted(expected.items()):
        path = os.path.join(SAMPLES, name)
        if not os.path.isfile(path):
            continue
        ext = name.rsplit(".", 1)[-1].lower()
        fmt = FMT_BY_EXT.get(ext, "raw")
        data = open(path, "rb").read()
        try:
            r = req(f"{base}/scans/upload?name={urllib.parse.quote(name)}&fmt={fmt}", args.key,
                    data=data, method="POST")
            sid = r["scan_id"]
        except Exception as exc:  # noqa: BLE001
            rows.append((name, exp["kind"], exp["expect_checks"], "-", "upload-error", str(exc), ""))
            missed_n += 1 if exp["kind"] == "malicious" else 0
            continue
        state = ""
        rec = {}
        t0 = time.time()
        while time.time() - t0 < args.timeout:
            rec = req(f"{base}/scans/{sid}", args.key)
            state = rec.get("state", "")
            if state in ("done", "error"):
                break
            time.sleep(2)
        found = sorted({f["check_id"] for f in rec.get("findings", [])})
        verdict = rec.get("verdict", "")
        if exp["kind"] == "malicious":
            hit = bool(set(found) & set(exp["expect_checks"]))
            detected_n += 1 if hit else 0
            missed_n += 0 if hit else 1
            mark = "OK" if hit else "MISS"
        else:
            fp = verdict in ("Malicious", "Dangerous") or any(
                f["severity"] in ("critical", "high") for f in rec.get("findings", []))
            fp_n += 1 if fp else 0
            mark = "OK" if not fp else "FALSE-POSITIVE"
        rows.append((name, exp["kind"], exp["expect_checks"], mark, verdict,
                     state, ", ".join(found[:8])))

    # политика аналитики (финальное решение)
    policy = {}
    if args.analytics_url:
        try:
            req(args.analytics_url.rstrip("/") + "/sync", args.key, data=b"", method="POST")
            time.sleep(2)
            data = req(args.analytics_url.rstrip("/") + "/api/scans", args.key)
            for r in data.get("scans", []):
                policy[r.get("name")] = (r.get("verdict"), (r.get("policy") or {}).get("action"))
        except Exception as exc:  # noqa: BLE001
            print(f"[warn] analytics: {exc}", file=sys.stderr)

    total_mal = sum(1 for v in expected.values() if v["kind"] == "malicious")
    total_ben = sum(1 for v in expected.values() if v["kind"] == "benign")
    L = ["# Отчёт: проверка системы на синтетическом корпусе уязвимостей", ""]
    L.append(f"- Дата: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    L.append(f"- Образцов: {len(rows)} (malicious={total_mal}, benign={total_ben})")
    L.append(f"- **Обнаружено (malicious): {detected_n}/{total_mal}**")
    L.append(f"- **Пропущено: {missed_n}**")
    L.append(f"- **Ложных срабатываний на benign: {fp_n}/{total_ben}**")
    L.append("")
    L.append("| Образец | Тип | Ожидаемые чек-иды | Результат | Вердикт (сервис) | Policy | State | Найдено |")
    L.append("|---------|-----|-------------------|-----------|------------------|--------|-------|---------|")
    for name, kind, checks, mark, verdict, state, found in rows:
        pv = policy.get(name)
        pol = f"{pv[0]}/{pv[1]}" if pv else "—"
        L.append(f"| {name} | {kind} | {', '.join(checks) or '—'} | {mark} | {verdict} | {pol} | {state} | {found or '—'} |")
    out = "\n".join(L) + "\n"
    open(args.out, "w").write(out)
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
