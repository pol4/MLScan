#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Единая тестовая среда Kata для LLM-инференса (v3, L1).

Формирует Job (один pod = одна микро-ВМ) с контейнерами: init `model-fetcher` (доставка модели из S3
в общий том), `engine` (customer-образ движка), `tetragon-agent` (in-guest eBPF), `probe-runner`
(запросы к OpenAI API на localhost). Проверяет достаточность ресурсов (GPU/RAM/диск) на LLM-пуле.
"""
from __future__ import annotations

NAMESPACE = "mlscan-sandbox-llm"


def resource_check(required: dict, available: dict) -> tuple[bool, str]:
    """required/available: {gpu:int, ram_gb:int, disk_gb:int}. Возвращает (ok, reason)."""
    for key in ("gpu", "ram_gb", "disk_gb"):
        need = int((required or {}).get(key, 0) or 0)
        have = int((available or {}).get(key, 0) or 0)
        if need > have:
            return False, f"insufficient {key}: need {need}, have {have}"
    return True, "ok"


def validate_job(job: dict) -> tuple[bool, str]:
    spec = (((job or {}).get("spec") or {}).get("template") or {}).get("spec") or {}
    if spec.get("runtimeClassName") != "kata":
        return False, "runtimeClassName должен быть kata"
    if spec.get("automountServiceAccountToken") is not False:
        return False, "automountServiceAccountToken должен быть false"
    names = [c.get("name") for c in spec.get("containers", [])]
    for need in ("engine", "tetragon-agent", "probe-runner"):
        if need not in names:
            return False, f"нет контейнера {need}"
    inits = [c.get("name") for c in spec.get("initContainers", [])]
    if "model-fetcher" not in inits:
        return False, "нет initContainer model-fetcher"
    vols = {v.get("name") for v in spec.get("volumes", [])}
    if not {"model", "events"} <= vols:
        return False, "нужны общие тома model и events"
    engine = next(c for c in spec["containers"] if c["name"] == "engine")
    if "@sha256:" not in engine.get("image", ""):
        return False, "engine image должен быть по digest"
    if not engine.get("resources", {}).get("limits"):
        return False, "у engine должны быть resources.limits"
    for c in spec["containers"]:
        sc = c.get("securityContext") or {}
        if sc.get("allowPrivilegeEscalation") is not False:
            return False, f"{c['name']}: нужен allowPrivilegeEscalation=false"
        if "ALL" not in (sc.get("capabilities", {}).get("drop") or []):
            return False, f"{c['name']}: нужен capabilities.drop=[ALL]"
        if sc.get("readOnlyRootFilesystem") is not True:
            return False, f"{c['name']}: нужен readOnlyRootFilesystem=true"
    return True, "ok"


def make_scan_job(*, scan_id: str, engine_image: str, model_sha256: str, model_key: str,
                  resources: dict | None = None, api_port: int = 8000, prompt_set: str = "",
                  fetcher_image: str = "", tetragon_image: str = "", probe_image: str = "",
                  namespace: str = NAMESPACE, model_volume_size: str = "500Gi") -> dict:
    res = resources or {"gpu": 1, "ram_gb": 64, "disk_gb": 120}
    limits = {"memory": f"{int(res.get('ram_gb', 64))}Gi", "cpu": "8",
              "ephemeral-storage": f"{int(res.get('disk_gb', 120))}Gi"}
    if int(res.get("gpu", 0) or 0) > 0:
        limits["nvidia.com/gpu"] = int(res["gpu"])
    hardened = {"runAsNonRoot": True, "readOnlyRootFilesystem": True,
                "allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]},
                "seccompProfile": {"type": "RuntimeDefault"}}
    tetragon_ctx = dict(hardened)
    tetragon_ctx["capabilities"] = {"drop": ["ALL"], "add": ["BPF", "PERFMON"]}
    fetcher_image = fetcher_image or engine_image
    tetragon_image = tetragon_image or engine_image
    probe_image = probe_image or engine_image
    return {
        "apiVersion": "batch/v1", "kind": "Job",
        "metadata": {"name": f"mlscan-llm-{scan_id}", "namespace": namespace,
                     "labels": {"app": "mlscan-llm", "scan_id": scan_id}},
        "spec": {
            "backoffLimit": 0, "ttlSecondsAfterFinished": 3600,
            "template": {
                "metadata": {"labels": {"app": "mlscan-llm", "scan_id": scan_id}},
                "spec": {
                    "runtimeClassName": "kata",
                    "automountServiceAccountToken": False,
                    "restartPolicy": "Never",
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 65532,
                                        "seccompProfile": {"type": "RuntimeDefault"}},
                    "initContainers": [{
                        "name": "model-fetcher", "image": fetcher_image,
                        "args": ["--key", model_key, "--dest", "/model", "--sha256", model_sha256],
                        "volumeMounts": [{"name": "model", "mountPath": "/model"}],
                    }],
                    "containers": [
                        {"name": "engine", "image": engine_image,
                         "args": ["--model", "/model", "--host", "127.0.0.1", "--port", str(api_port)],
                         "ports": [{"name": "openai", "containerPort": api_port}],
                         "resources": {"limits": limits},
                         "securityContext": dict(hardened),
                         "volumeMounts": [{"name": "model", "mountPath": "/model", "readOnly": True}]},
                        {"name": "tetragon-agent", "image": tetragon_image,
                         "securityContext": tetragon_ctx,
                         "volumeMounts": [{"name": "events", "mountPath": "/events"}]},
                        {"name": "probe-runner", "image": probe_image,
                         "securityContext": dict(hardened),
                         "args": ["--endpoint", f"http://127.0.0.1:{api_port}/v1",
                                  "--prompt-set", prompt_set],
                         "volumeMounts": [{"name": "events", "mountPath": "/events"}]},
                    ],
                    "volumes": [
                        {"name": "model", "emptyDir": {"sizeLimit": model_volume_size}},
                        {"name": "events", "emptyDir": {}},
                    ],
                },
            },
        },
    }
