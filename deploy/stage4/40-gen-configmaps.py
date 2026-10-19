#!/usr/bin/env python3
"""Генерирует ConfigMap'ы Этапа 4:
 * mlscan-integrations-code — код сервиса интеграций;
 * mlscan-intel             — seed threat-intel (known-bad sha256 демо-образцов + watch-checks)."""
import glob
import hashlib
import json
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
NS = "mlscan-integrations"


def indent(text: str, pad: int = 4) -> str:
    return "".join(" " * pad + ln + "\n" for ln in text.splitlines())


def main() -> int:
    code = open(os.path.join(ROOT, "deploy", "stage4", "service", "mlscan_integrations.py"),
                encoding="utf-8").read()
    known_bad = []
    for f in sorted(glob.glob(os.path.join(ROOT, "poc", "scan", "evil*.pkl"))):
        known_bad.append(hashlib.sha256(open(f, "rb").read()).hexdigest())
    intel = {"known_bad_sha256": known_bad, "watch_checks": ["A-01", "F-32", "F-31", "F-30"]}

    out = ("apiVersion: v1\nkind: ConfigMap\nmetadata:\n"
           f"  name: mlscan-integrations-code\n  namespace: {NS}\n"
           "  labels: {app.kubernetes.io/part-of: mlscan, mlscan.io/stage: \"4\"}\n"
           "data:\n  mlscan_integrations.py: |\n" + indent(code))
    out += ("---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n"
            f"  name: mlscan-intel\n  namespace: {NS}\n"
            "  labels: {app.kubernetes.io/part-of: mlscan, mlscan.io/stage: \"4\"}\n"
            "data:\n  intel.json: |\n" + indent(json.dumps(intel, ensure_ascii=False, indent=2)))
    sys.stdout.write(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
