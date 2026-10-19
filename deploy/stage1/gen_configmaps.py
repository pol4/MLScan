#!/usr/bin/env python3
"""Генерирует ConfigMap'ы Stage 1 из исходников PoC:
 * mlscan-harness  — in-cluster harness (HARNESS_SRC из poc/mlscan_poc.py);
 * mlscan-samples  — демонстрационные pickle из poc/scan (binaryData).
Печатает YAML в stdout (для `kubectl apply -f -`)."""
import base64
import glob
import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
NS = "mlscan-sandbox"


def indent(text: str, pad: int = 4) -> str:
    prefix = " " * pad
    lines = text.splitlines()
    return "".join(prefix + ln + "\n" for ln in lines)


def main() -> int:
    src = open(os.path.join(ROOT, "poc", "mlscan_poc.py"), encoding="utf-8").read()
    m = re.search(r"HARNESS_SRC = r'''(.*?)'''", src, re.S)
    if not m:
        print("HARNESS_SRC not found in poc/mlscan_poc.py", file=sys.stderr)
        return 1
    harness = m.group(1)

    out = [
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n"
        f"  name: mlscan-harness\n  namespace: {NS}\n"
        "  labels: {app.kubernetes.io/part-of: mlscan, mlscan.io/stage: \"1\"}\n"
        "data:\n  harness.py: |\n" + indent(harness)
    ]

    samples = sorted(glob.glob(os.path.join(ROOT, "poc", "scan", "*.pkl")))
    out.append(
        "---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n"
        f"  name: mlscan-samples\n  namespace: {NS}\n"
        "  labels: {app.kubernetes.io/part-of: mlscan, mlscan.io/stage: \"1\"}\n"
        "binaryData:\n"
    )
    for f in samples:
        data = base64.b64encode(open(f, "rb").read()).decode()
        out.append(f"  {os.path.basename(f)}: {data}\n")

    sys.stdout.write("".join(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
