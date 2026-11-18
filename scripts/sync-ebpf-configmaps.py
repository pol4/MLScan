#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Синхронизировать ConfigMap `mlscan-ebpf-agent` из источника агента.

Источник: ``deploy/v3/sandbox/kata-btf/ebpf_agent.py``. Копии (иначе ArgoCD видит
их рассинхрон): ``deploy/tenant/workloads/{sandbox,gpu}/ebpf-agent.yaml``.

Запуск: ``python3 scripts/sync-ebpf-configmaps.py`` (идемпотентно; печатает, что изменилось).
"""
from __future__ import annotations

import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "deploy", "v3", "sandbox", "kata-btf", "ebpf_agent.py")
TARGETS = [
    (os.path.join(ROOT, "deploy", "tenant", "workloads", "sandbox", "ebpf-agent.yaml"),
     "t-mlscan-sandbox", []),
    (os.path.join(ROOT, "deploy", "tenant", "workloads", "gpu", "ebpf-agent.yaml"),
     "t-mlscan-gpu",
     ["# Generated copy of ../sandbox/ebpf-agent.yaml for the t-mlscan-gpu LLM path.",
      "# Keep in sync with the sandbox source (same ConfigMap data, GPU namespace)."]),
]


def render(source: str, namespace: str, header: list[str]) -> str:
    out: list[str] = []
    out.extend(header)
    out.append("apiVersion: v1")
    out.append("data:")
    out.append("  ebpf_agent.py: |")
    for line in source.splitlines():
        out.append(("    " + line) if line.strip() else "")
    out.append("kind: ConfigMap")
    out.append("metadata:")
    out.append("  creationTimestamp: null")
    out.append("  name: mlscan-ebpf-agent")
    out.append(f"  namespace: {namespace}")
    out.append("  labels: {app.kubernetes.io/part-of: mlscan}")
    return "\n".join(out) + "\n"


def main() -> int:
    with open(SRC, encoding="utf-8") as fh:
        source = fh.read()
    if source and not source.endswith("\n"):
        source += "\n"
    for path, ns, header in TARGETS:
        want = render(source.rstrip("\n"), ns, header)
        have = ""
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                have = fh.read()
        if have == want:
            print(f"[sync] {os.path.relpath(path, ROOT)}: без изменений")
            continue
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(want)
        print(f"[sync] {os.path.relpath(path, ROOT)}: обновлён")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
