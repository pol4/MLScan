#!/usr/bin/env python3
"""Генерирует ConfigMap'ы Этапа 2:
 * mlscan-poc-lib       — общий анализ (poc/mlscan_poc.py), импортируется сервисом как mlscan_poc;
 * mlscan-testing-code  — код сервиса тестирования.
Печатает YAML в stdout."""
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
NS = "mlscan-testing"


def indent(text: str, pad: int = 4) -> str:
    prefix = " " * pad
    return "".join(prefix + ln + "\n" for ln in text.splitlines())


def cm(name: str, key: str, text: str) -> str:
    return (
        "apiVersion: v1\nkind: ConfigMap\nmetadata:\n"
        f"  name: {name}\n  namespace: {NS}\n"
        "  labels: {app.kubernetes.io/part-of: mlscan, mlscan.io/stage: \"2\"}\n"
        f"data:\n  {key}: |\n" + indent(text)
    )


def main() -> int:
    poc = open(os.path.join(ROOT, "poc", "mlscan_poc.py"), encoding="utf-8").read()
    svc = open(os.path.join(ROOT, "deploy", "stage2", "service", "mlscan_testing.py"),
               encoding="utf-8").read()
    out = cm("mlscan-poc-lib", "mlscan_poc.py", poc)
    out += "---\n" + cm("mlscan-testing-code", "mlscan_testing.py", svc)
    sys.stdout.write(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
