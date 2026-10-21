#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Генератор БЕЗОПАСНЫХ (без уязвимостей и закладок) примеров сложных форматов ML-моделей.

Нужен, чтобы проверять систему «с обеих сторон»: на образцах с закладками
(`gen_corpus.py`) и на корректных моделях — у последних не должно быть находок, а динамика
обязана реально загрузить модель (иначе сканирование честно помечается как неполное).

Что создаётся (форматы — реальные, не «наборы байт»):

  safetensors (mmap), numpy .npz, torch .pt, HDF5 .h5, ONNX (реальная модель),
  GGUF (метаданные + тензор), Keras .keras (zip: config.json + weights.h5),
  архивы .zip/.tar.gz, joblib/dill/cloudpickle, tokenizer.json, MCP-манифест,
  YAML/XML-конфиги, PNG-картинка, карточка модели.

Крупные примеры (`--large-mb`) генерируются «на лету» и по умолчанию НЕ кладутся в репозиторий:
их можно сразу отправить в сервис тестирования (`--upload URL --key K`).

Запуск со всеми библиотеками — в образе песочницы (там есть torch/onnx/h5py/gguf):

    kubectl -n mlscan-data run gen-benign --rm -i --restart=Never \
      --image=localhost:32000/mlscan-sandbox:v3 --command -- \
      python3 - --out /tmp/benign < tests/vulnerabilities/gen_benign_formats.py
    kubectl cp mlscan-data/gen-benign:/tmp/benign ./tests/vulnerabilities/samples_benign
"""
from __future__ import annotations

import argparse
import io
import json
import os
import struct
import sys
import tarfile
import time
import zipfile

EXPECT: dict[str, dict] = {}
FILES: list[tuple[str, bytes]] = []


def add(name: str, data: bytes, note: str = "") -> None:
    FILES.append((name, data))
    EXPECT[name] = {"expect_checks": [], "kind": "benign", "note": note}
    print(f"  {name:42} {len(data):>12,} B  {note}")


def _png(w: int, h: int, rgb: tuple[int, int, int]) -> bytes:
    """Минимальный корректный PNG (без PIL): один IDAT, без trailing-данных."""
    import zlib

    def chunk(tag: bytes, payload: bytes) -> bytes:
        return (struct.pack(">I", len(payload)) + tag + payload
                + struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF))

    raw = b"".join(b"\x00" + bytes(rgb) * w for _ in range(h))
    ihdr = struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(raw, 6)) + chunk(b"IEND", b""))


def _need(mod: str):
    try:
        return __import__(mod)
    except Exception:  # noqa: BLE001
        print(f"  (пропуск: нет модуля {mod})", file=sys.stderr)
        return None


# --------------------------------------------------------------------------
# Небольшие корректные примеры
# --------------------------------------------------------------------------
def gen_safetensors(small: bool = True) -> None:
    import numpy as np
    from safetensors.numpy import save

    if small:
        tensors = {"embed.weight": np.random.RandomState(0).randn(64, 32).astype("float32"),
                   "head.bias": np.zeros((16,), dtype="float32")}
        add("safe_real_safetensors.safetensors", save(tensors),
            "safetensors: 2 тензора, mmap-загрузка")
        # half/bfloat16 вариант — тоже корректный
        tensors_h = {"w": np.random.RandomState(1).randn(32, 32).astype("float16")}
        add("safe_real_safetensors_f16.safetensors", save(tensors_h), "safetensors f16")


def gen_numpy() -> None:
    import numpy as np
    buf = io.BytesIO()
    np.savez(buf, weights=np.zeros((128, 64), dtype="float32"),
             bias=np.ones((64,), dtype="float32"),
             config=np.array([1, 2, 3], dtype="int64"))
    add("safe_real_numpy.npz", buf.getvalue(), "numpy npz: 3 массива")


def gen_torch(small: bool = True) -> None:
    torch = _need("torch")
    if torch is None:
        return
    if small:
        net = torch.nn.Sequential(torch.nn.Linear(32, 16), torch.nn.ReLU(), torch.nn.Linear(16, 4))
        buf = io.BytesIO()
        torch.save({"state_dict": net.state_dict(),
                    "meta": {"framework": "pytorch", "task": "demo"}}, buf)
        add("safe_real_torch.pt", buf.getvalue(), "torch: state_dict + метаданные")


def gen_hdf5() -> None:
    h5py = _need("h5py")
    if h5py is None:
        return
    buf = io.BytesIO()
    with h5py.File(buf, "w") as f:
        f.create_dataset("dense/kernel", data=[[0.0] * 32] * 16, dtype="float32")
        f.create_dataset("dense/bias", data=[0.0] * 32, dtype="float32")
        f.attrs["format"] = "keras"
        f.attrs["backend"] = "tensorflow"
    add("safe_real_hdf5.h5", buf.getvalue(), "HDF5: 2 датасета + атрибуты")


def gen_onnx() -> None:
    onnx = _need("onnx")
    if onnx is None:
        return
    import numpy as np
    from onnx import TensorProto, helper, numpy_helper

    w = numpy_helper.from_array(np.random.RandomState(2).randn(16, 8).astype("float32"), name="w")
    b = numpy_helper.from_array(np.zeros((8,), dtype="float32"), name="b")
    node = helper.make_node("MatMul", ["x", "w"], ["h"])
    node2 = helper.make_node("Add", ["h", "b"], ["y"])
    graph = helper.make_graph(
        [node, node2], "safe_demo",
        [helper.make_tensor_value_info("x", TensorProto.FLOAT, [1, 16])],
        [helper.make_tensor_value_info("y", TensorProto.FLOAT, [1, 8])],
        initializer=[w, b])
    model = helper.make_model(graph, producer_name="mlscan-synthetic",
                              opset_imports=[helper.make_opsetid("", 13)])
    model.ir_version = 8
    onnx.checker.check_model(model)
    add("safe_real_onnx.onnx", model.SerializeToString(),
        "ONNX: MatMul+Add, opset 13, реальный инференс")


def gen_gguf() -> None:
    gguf = _need("gguf")
    if gguf is None:
        return
    import numpy as np
    from gguf import GGUFWriter

    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".gguf", delete=False) as tf:
        tmp = tf.name
    w = GGUFWriter(tmp, "mlscan-synthetic-safe")
    w.add_name("safe-demo")
    w.add_uint32("general.architecture", 1)
    w.add_string("general.description", "benign synthetic gguf for scanner tests")
    w.add_tensor("token_embd.weight", np.zeros((64, 8), dtype="float32"))
    w.write_header_to_file()
    w.write_kv_data_to_file()
    w.write_tensors_to_file()
    w.close()
    with open(tmp, "rb") as f:
        data = f.read()
    os.unlink(tmp)
    add("safe_real_gguf.gguf", data, "GGUF: метаданные + тензор")


def gen_keras() -> None:
    h5py = _need("h5py")
    if h5py is None:
        return
    wbuf = io.BytesIO()
    with h5py.File(wbuf, "w") as f:
        f.create_dataset("layers/dense/vars/0", data=[[0.0] * 8] * 16, dtype="float32")
    cfg = {
        "class_name": "Sequential",
        "config": {"name": "safe_demo", "layers": [
            {"class_name": "Dense", "config": {"units": 8, "activation": "relu", "use_bias": True}}]},
        "keras_version": "3.0.0", "backend": "tensorflow",
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("config.json", json.dumps(cfg))
        z.writestr("metadata.json", json.dumps({"keras_version": "3.0.0"}))
        z.writestr("model.weights.h5", wbuf.getvalue())
    add("safe_real_keras.keras", buf.getvalue(), "Keras .keras: config + weights.h5")


def gen_archives() -> None:
    import numpy as np
    payload_onnx = None
    try:
        from onnx import TensorProto, helper, numpy_helper  # noqa: F401
        import onnx
        import numpy as _np
        w = numpy_helper.from_array(_np.ones((4, 4), dtype="float32"), name="w")
        g = helper.make_graph([helper.make_node("Identity", ["x"], ["y"])], "g",
                              [helper.make_tensor_value_info("x", TensorProto.FLOAT, [1, 4])],
                              [helper.make_tensor_value_info("y", TensorProto.FLOAT, [1, 4])],
                              initializer=[w])
        m = helper.make_model(g, opset_imports=[helper.make_opsetid("", 13)])
        m.ir_version = 8
        payload_onnx = m.SerializeToString()
    except Exception:  # noqa: BLE001
        payload_onnx = b"\x08\x07" + b"\x00" * 64
    tokenizer = {"model": {"type": "BPE", "vocab": {"hello": 0, "world": 1}},
                 "normalizer": {"type": "Lowercase"}, "added_tokens": []}
    z_buf = io.BytesIO()
    with zipfile.ZipFile(z_buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("model.onnx", payload_onnx)
        z.writestr("config.json", json.dumps({"model_type": "demo", "hidden_size": 8}))
        z.writestr("tokenizer.json", json.dumps(tokenizer))
        z.writestr("README.md", "# Demo model\nA benign demo model package.\n")
        z.writestr("weights.safetensors", b"\x00" * 128)
    add("safe_real_archive.zip", z_buf.getvalue(), "zip: onnx + config + tokenizer + card")

    t_buf = io.BytesIO()
    with tarfile.open(fileobj=t_buf, mode="w:gz") as t:
        for name, data in (("model.onnx", payload_onnx),
                           ("config.json", json.dumps({"model_type": "demo"}).encode()),
                           ("README.md", b"# Demo model\nBenign package.\n")):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    add("safe_real_archive.tar.gz", t_buf.getvalue(), "tar.gz: onnx + config + card")
    _ = np


def gen_pickles() -> None:
    import pickle

    add("safe_real_pickle.pkl", pickle.dumps({"weights": [1.0, 2.0, 3.0], "meta": "demo"}),
        "pickle: обычный dict")
    for mod, ext in (("joblib", "joblib"), ("dill", "dill"), ("cloudpickle", "cloudpickle")):
        m = _need(mod)
        if m is None:
            continue
        obj = {"model": "safe", "params": [1, 2, 3]}
        try:
            if mod == "joblib":
                import tempfile
                with tempfile.NamedTemporaryFile(suffix=".joblib", delete=False) as tf:
                    tmp = tf.name
                m.dump(obj, tmp)
                data = open(tmp, "rb").read()
                os.unlink(tmp)
            else:
                data = m.dumps(obj)
        except Exception as exc:  # noqa: BLE001
            print(f"  ({mod}: {exc})", file=sys.stderr)
            continue
        add(f"safe_real.{ext}", data, f"{mod}: безопасный объект")


def gen_texts() -> None:
    add("safe_tokenizer_bpe.json",
        json.dumps({"model": {"type": "BPE", "vocab": {"hello": 0, "world": 1, "\u0120": 2}},
                    "normalizer": {"type": "Lowercase"},
                    "added_tokens": [{"id": 0, "content": "<s>", "special": True}]}).encode(),
        "tokenizer: корректный BPE без переопределений/ReDoS")
    add("safe_mcp_manifest.json",
        json.dumps({"mcpServers": {"docs": {"url": "https://docs.example.com/mcp",
                                            "capabilities": ["resources"]}}}).encode(),
        "MCP-манифест без запуска команд")
    add("safe_config.yaml", b"model:\n  hidden_size: 8\n  layers: 2\ntraining:\n  lr: 0.001\n",
        "YAML-конфиг без unsafe-тегов")
    add("safe_config.xml", b'<?xml version="1.0"?><config><hidden_size>8</hidden_size></config>',
        "XML без DOCTYPE/ENTITY")
    add("safe_card_clean.md",
        b"# Demo model\n\nA small image classifier for documentation examples.\n"
        b"License: MIT. Intended for research.\n", "карточка без prompt-injection")
    add("safe_real_image.png", _png(48, 48, (12, 34, 56)), "PNG-картинка без trailing-данных")


def gen_extra_formats() -> None:
    """Форматы «Волны 4»: ноутбуки, скрипты, TorchScript, MLflow, SavedModel,
    TFLite, CoreML, PMML, датасеты Parquet/Arrow — корректные версии."""
    # ноутбук: чистый код обучения, без shell-команд и injection
    nb = {
        "cells": [
            {"cell_type": "markdown", "metadata": {}, "source": [
                "# Demo training\n", "A small image classifier for documentation.\n"]},
            {"cell_type": "code", "metadata": {}, "execution_count": None, "outputs": [],
             "source": ["import torch\n", "model = torch.nn.Linear(8, 4)\n",
                        "print(model(torch.zeros(1, 8)).shape)\n"]},
        ],
        "metadata": {"kernelspec": {"name": "python3", "display_name": "Python 3"}},
        "nbformat": 4, "nbformat_minor": 5,
    }
    add("safe_notebook.ipynb", json.dumps(nb).encode(), "notebook: чистый код обучения")

    add("safe_script.sh",
        b"#!/bin/sh\nset -e\npython3 -m venv .venv\n. .venv/bin/activate\n"
        b"pip install -r requirements.txt\npython3 train.py --epochs 3\n",
        "shell-скрипт: обучение, без загрузок и URL")

    # TorchScript (реальная сериализация torch.jit) — проверяем отсутствие ложного EXEC-03
    torch = _need("torch")
    if torch is not None:
        buf = io.BytesIO()
        net = torch.nn.Sequential(torch.nn.Linear(8, 4), torch.nn.ReLU())
        scripted = torch.jit.trace(net, torch.zeros(1, 8))
        torch.jit.save(scripted, buf)
        add("safe_torchscript.pt", buf.getvalue(), "TorchScript (torch.jit) — легитимный code/")

    # MLflow-модель без кода и внешних источников
    m_buf = io.BytesIO()
    with zipfile.ZipFile(m_buf, "w") as z:
        z.writestr("MLmodel", "artifact_path: model\nflavors:\n  sklearn:\n"
                              "    pickled_model: model.pkl\n    sklearn_version: 1.5.0\n")
        z.writestr("conda.yaml", "name: env\nchannels: [conda-forge]\n"
                                 "dependencies:\n  - python=3.12\n  - pip\n")
        z.writestr("requirements.txt", "scikit-learn==1.5.0\n")
        z.writestr("python_env.yaml", "python: 3.12.0\n")
        import pickle as _pkl
        z.writestr("model.pkl", _pkl.dumps({"coef": [0.1, 0.2], "intercept": 0.0}))
    add("safe_mlflow.zip", m_buf.getvalue(), "MLflow-модель без кода и URL")

    # SavedModel без Python-операций
    s_buf = io.BytesIO()
    with zipfile.ZipFile(s_buf, "w") as z:
        z.writestr("saved_model.pb", b"\x1a\x08graphdef" + b"\x00" * 64)
        z.writestr("variables/variables.index", b"\x00" * 128)
        z.writestr("assets/tokenizer.json", json.dumps({"model": {"type": "BPE"}}).encode())
    add("safe_savedmodel.zip", s_buf.getvalue(), "SavedModel без py_function")

    add("safe_tflite.tflite", b"TFL3" + b"\x00" * 24 + b"CONV_2D" + b"FULLY_CONNECTED" + b"\x00" * 32,
        "TFLite со встроенными операциями")
    add("safe_coreml.mlmodel", b"\x0a\x0c" + b"convolution" + b"innerProduct" + b"\x00" * 32,
        "CoreML со стандартными слоями")
    add("safe_pmml.pmml",
        b'<?xml version="1.0"?><PMML version="4.4"><Header/><DataDictionary>'
        b'<DataField name="x" optype="continuous" dataType="double"/></DataDictionary>'
        b'<RegressionModel functionName="regression"/></PMML>',
        "PMML без Extension/Java")

    # Датасеты Parquet/Arrow (pyarrow)
    if _need("pyarrow") is not None:
        import pyarrow as pa
        import pyarrow.parquet as pq
        table = pa.table({"feature": [0.0, 1.0, 2.0], "label": [0, 1, 0]})
        buf = io.BytesIO()
        pq.write_table(table, buf)
        add("safe_parquet.parquet", buf.getvalue(), "Parquet: обычная схема")
        buf2 = io.BytesIO()
        with pa.ipc.new_file(buf2, table.schema) as w:
            w.write_table(table)
        add("safe_arrow.arrow", buf2.getvalue(), "Arrow IPC: обычная схема")


# --------------------------------------------------------------------------
# Крупные корректные примеры (по умолчанию не сохраняются в репозиторий)
# --------------------------------------------------------------------------
def gen_large(mb: int) -> None:
    import numpy as np

    n = max(1024, int((mb * 1024 * 1024) // 4))          # элементов float32
    side = int(n ** 0.5)
    side -= side % 128
    elems = side * side
    print(f"  крупные примеры: массив {side}x{side} (~{elems * 4 / 1e6:.0f} МБ)")
    arr = np.zeros((side, side), dtype="float32")
    arr.reshape(-1)[::4096] = 1.0                        # немного ненулевых значений

    # 1) safetensors (mmap)
    try:
        from safetensors.numpy import save
        add("safe_large_safetensors.safetensors", save({"embed.weight": arr}),
            f"крупный safetensors ~{elems * 4 / 1e6:.0f} МБ")
    except Exception as exc:  # noqa: BLE001
        print("  (safetensors:", exc, ")")

    # 2) numpy npz
    buf = io.BytesIO()
    np.savez(buf, embed=arr)
    add("safe_large_numpy.npz", buf.getvalue(), f"крупный npz ~{elems * 4 / 1e6:.0f} МБ")

    # 3) HDF5
    if _need("h5py"):
        import h5py
        buf = io.BytesIO()
        with h5py.File(buf, "w") as f:
            f.create_dataset("model/embed", data=arr, dtype="float32", chunks=(128, 128))
        add("safe_large_hdf5.h5", buf.getvalue(), f"крупный HDF5 ~{elems * 4 / 1e6:.0f} МБ")

    # 4) torch
    torch = _need("torch")
    if torch is not None:
        buf = io.BytesIO()
        torch.save({"state_dict": {"embed.weight": torch.from_numpy(arr)}, "meta": {"task": "demo"}}, buf)
        add("safe_large_torch.pt", buf.getvalue(), f"крупный torch ~{elems * 4 / 1e6:.0f} МБ")

    # 5) ONNX с крупным инициализатором (инференс не запускаем: вход > 1M элементов)
    if _need("onnx"):
        import onnx
        from onnx import TensorProto, helper, numpy_helper
        w = numpy_helper.from_array(arr, name="w")
        g = helper.make_graph([helper.make_node("MatMul", ["x", "w"], ["y"])], "large_demo",
                              [helper.make_tensor_value_info("x", TensorProto.FLOAT, [1, side])],
                              [helper.make_tensor_value_info("y", TensorProto.FLOAT, [1, side])],
                              initializer=[w])
        m = helper.make_model(g, opset_imports=[helper.make_opsetid("", 13)])
        m.ir_version = 8
        onnx.checker.check_model(m)
        add("safe_large_onnx.onnx", m.SerializeToString(),
            f"крупный ONNX ~{elems * 4 / 1e6:.0f} МБ")


# --------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="Генератор безопасных примеров сложных форматов")
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "samples_benign"))
    ap.add_argument("--large-mb", type=int, default=0, help="размер крупных примеров (МБ); 0 = не создавать")
    ap.add_argument("--upload", help="URL сервиса тестирования (например http://127.0.0.1:8080)")
    ap.add_argument("--verify", action="store_true",
                    help="после загрузки дождаться вердиктов и показать их (coverage/находки)")
    ap.add_argument("--key", help="API-ключ для загрузки")
    ap.add_argument("--json", default=None, help="файл ожиданий (по умолчанию <out>/expected_benign.json)")
    args = ap.parse_args()

    print("== небольшие корректные примеры")
    gen_safetensors()
    gen_numpy()
    gen_torch()
    gen_hdf5()
    gen_onnx()
    gen_gguf()
    gen_keras()
    gen_archives()
    gen_pickles()
    gen_texts()
    gen_extra_formats()
    if args.large_mb:
        print("== крупные корректные примеры")
        gen_large(args.large_mb)

    if args.upload:
        import urllib.request
        print(f"== загрузка в {args.upload}")
        scan_ids: list[tuple[str, str]] = []
        for name, data in FILES:
            ext = name.rsplit(".", 1)[-1].lower()
            fmt = {"pt": "torch", "pth": "torch", "npz": "numpy", "h5": "hdf5", "keras": "keras",
                   "onnx": "onnx", "gguf": "gguf", "safetensors": "safetensors",
                   "joblib": "joblib", "dill": "dill", "cloudpickle": "cloudpickle",
                   "zip": "zip", "gz": "tar", "png": "image", "md": "card",
                   "json": "config", "yaml": "config", "xml": "xml"}.get(ext, "pickle")
            req = urllib.request.Request(
                f"{args.upload.rstrip('/')}/scans/upload?name={name}&fmt={fmt}", data=data,
                method="POST", headers={"Authorization": f"Bearer {args.key}"})
            with urllib.request.urlopen(req, timeout=1800) as r:
                res = json.loads(r.read().decode())
            scan_ids.append((name, res.get("scan_id")))
            print(f"  {name:42} -> scan {res.get('scan_id')} ({len(data):,} B)")
        if args.verify:
            print("== вердикты (ожидание done)")
            base = args.upload.rstrip("/")
            bad = 0
            for name, sid in scan_ids:
                for _ in range(240):
                    req = urllib.request.Request(f"{base}/scans/{sid}",
                                                 headers={"Authorization": f"Bearer {args.key}"})
                    with urllib.request.urlopen(req, timeout=120) as r:
                        rec = json.loads(r.read().decode())
                    if rec.get("state") in ("done", "error"):
                        break
                    time.sleep(3)
                cov = rec.get("coverage") or {}
                verdict = rec.get("verdict")
                checks = sorted({f["check_id"] for f in rec.get("findings", [])})
                ok = verdict == "Safe" and cov.get("complete") is True
                bad += 0 if ok else 1
                print(f"  {name:42} {verdict:>13} complete={cov.get('complete')} "
                      f"findings={checks} {'OK' if ok else '<-- ПРОВЕРИТЬ'}")
            print(f"\nБезопасных и полностью проверенных: {len(scan_ids) - bad}/{len(scan_ids)}")
    else:
        os.makedirs(args.out, exist_ok=True)
        for name, data in FILES:
            with open(os.path.join(args.out, name), "wb") as f:
                f.write(data)
        path = args.json or os.path.join(args.out, "expected_benign.json")
        with open(path, "w") as f:
            json.dump(EXPECT, f, ensure_ascii=False, indent=2)
        print(f"\nЗаписано файлов: {len(FILES)} -> {args.out}")
        print(f"Ожидания: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
