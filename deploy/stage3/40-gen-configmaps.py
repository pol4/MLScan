#!/usr/bin/env python3
"""Генерирует ConfigMap mlscan-analytics-code (код аналитического движка)."""
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
NS = "mlscan-analytics"


def indent(text: str, pad: int = 4) -> str:
    return "".join(" " * pad + ln + "\n" for ln in text.splitlines())


def main() -> int:
    code = open(os.path.join(ROOT, "deploy", "stage3", "service", "mlscan_analytics.py"),
                encoding="utf-8").read()
    out = ("apiVersion: v1\nkind: ConfigMap\nmetadata:\n"
           f"  name: mlscan-analytics-code\n  namespace: {NS}\n"
           "  labels: {app.kubernetes.io/part-of: mlscan, mlscan.io/stage: \"3\"}\n"
           "data:\n  mlscan_analytics.py: |\n" + indent(code))
    sys.stdout.write(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
