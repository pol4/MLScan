#!/usr/bin/env python3
"""Генерирует ConfigMap'ы Этапа 5:
 * mlscan-ops-code        — код ops-сервиса (namespace mlscan-ops);
 * mlscan-golden          — golden-метки (name -> malicious|benign);
 * mlscan-golden-samples  — демо-образцы (binaryData) для непрерывного retest;
 * mlscan-redteam         — скрипт red-team/эскейп-теста (namespace mlscan-sandbox)."""
import base64
import glob
import json
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
OPS_NS = "mlscan-ops"
SANDBOX_NS = "mlscan-sandbox"


def indent(text: str, pad: int = 4) -> str:
    return "".join(" " * pad + ln + "\n" for ln in text.splitlines())


def main() -> int:
    ops_code = open(os.path.join(ROOT, "deploy", "stage5", "service", "mlscan_ops.py"),
                    encoding="utf-8").read()
    redteam = open(os.path.join(ROOT, "deploy", "stage5", "service", "redteam.py"),
                   encoding="utf-8").read()
    samples = sorted(glob.glob(os.path.join(ROOT, "poc", "scan", "*.pkl")))

    labels = {}
    for f in samples:
        n = os.path.basename(f)
        labels[n] = "malicious" if n.startswith("evil") else "benign"

    out = ("apiVersion: v1\nkind: ConfigMap\nmetadata:\n"
           f"  name: mlscan-ops-code\n  namespace: {OPS_NS}\n"
           "  labels: {app.kubernetes.io/part-of: mlscan, mlscan.io/stage: \"5\"}\n"
           "data:\n  mlscan_ops.py: |\n" + indent(ops_code))
    out += ("---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n"
            f"  name: mlscan-golden\n  namespace: {OPS_NS}\n"
            "  labels: {app.kubernetes.io/part-of: mlscan, mlscan.io/stage: \"5\"}\n"
            "data:\n  golden.json: |\n" + indent(json.dumps(labels, ensure_ascii=False, indent=2)))
    out += ("---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n"
            f"  name: mlscan-golden-samples\n  namespace: {OPS_NS}\n"
            "  labels: {app.kubernetes.io/part-of: mlscan, mlscan.io/stage: \"5\"}\n"
            "binaryData:\n")
    for f in samples:
        out += f"  {os.path.basename(f)}: {base64.b64encode(open(f,'rb').read()).decode()}\n"
    out += ("---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n"
            f"  name: mlscan-redteam\n  namespace: {SANDBOX_NS}\n"
            "  labels: {app.kubernetes.io/part-of: mlscan, mlscan.io/stage: \"5\"}\n"
            "data:\n  redteam.py: |\n" + indent(redteam))
    sys.stdout.write(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
