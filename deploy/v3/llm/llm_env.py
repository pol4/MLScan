#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Единая тестовая среда Kata для LLM-инференса (v3, L1).

Формирует Job (один pod = одна микро-ВМ) с контейнерами: init `model-fetcher` (доставка модели из S3
в общий том), `engine` (customer-образ движка), `tetragon-agent` (in-guest eBPF), `probe-runner`
(запросы к OpenAI API на localhost). Проверяет достаточность ресурсов (GPU/RAM/диск) на LLM-пуле.
"""
from __future__ import annotations

import os

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
    if spec.get("runtimeClassName") not in ("kata", "kata-btf", "nvidia"):
        return False, "runtimeClassName должен быть kata/kata-btf/nvidia"
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
                  namespace: str = NAMESPACE, model_volume_size: str = "500Gi",
                  runtime_class: str = "kata", mount_dev: bool = False,
                  cuda_visible_devices: str = "") -> dict:
    res = resources or {"gpu": 1, "ram_gb": 64, "disk_gb": 120}
    limits = {"memory": f"{int(res.get('ram_gb', 64))}Gi", "cpu": "8",
              "ephemeral-storage": f"{int(res.get('disk_gb', 120))}Gi"}
    if int(res.get("gpu", 0) or 0) > 0:
        limits["nvidia.com/gpu"] = int(res["gpu"])
    engine_env = []
    if int(res.get("gpu", 0) or 0) > 0 or mount_dev:
        engine_env.append({"name": "NVIDIA_VISIBLE_DEVICES", "value": "all"})
        if cuda_visible_devices:
            engine_env.append({"name": "CUDA_VISIBLE_DEVICES", "value": str(cuda_visible_devices)})
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
                    "runtimeClassName": runtime_class,
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
                         **({"env": engine_env} if engine_env else {}),
                         "args": ["--model", "/model", "--host", "127.0.0.1", "--port", str(api_port)],
                         "ports": [{"name": "openai", "containerPort": api_port}],
                         "resources": {"limits": limits},
                         "securityContext": dict(hardened),
                         "volumeMounts": ([{"name": "model", "mountPath": "/model", "readOnly": True}]
                                          + ([{"name": "dev", "mountPath": "/dev"}] if mount_dev else []))},
                        {"name": "tetragon-agent", "image": tetragon_image,
                         "securityContext": tetragon_ctx,
                         "volumeMounts": [{"name": "events", "mountPath": "/events"}]},
                        {"name": "probe-runner", "image": probe_image,
                         "securityContext": dict(hardened),
                         "args": ["--endpoint", f"http://127.0.0.1:{api_port}/v1",
                                  "--prompt-set", prompt_set],
                         "volumeMounts": [{"name": "events", "mountPath": "/events"}]},
                    ],
                    "volumes": ([{"name": "model", "emptyDir": {"sizeLimit": model_volume_size}},
                                 {"name": "events", "emptyDir": {}}]
                                + ([{"name": "dev", "hostPath": {"path": "/dev"}}] if mount_dev else [])),
                },
            },
        },
    }


# --- N2: запускаемый job теста bundle (реальный движок + набор вопросов -> /llm/score) ----------
_FETCH_SRC = (
    "import hashlib,os,sys,urllib.request\n"
    "url=os.environ['FETCH_URL']; dest=os.environ.get('FETCH_DEST','/model/model.gguf')\n"
    "sha=os.environ.get('FETCH_SHA','')\n"
    "os.makedirs(os.path.dirname(dest),exist_ok=True)\n"
    "h=hashlib.sha256(); op=urllib.request.build_opener(urllib.request.ProxyHandler({}))\n"
    "with op.open(url,timeout=1800) as r, open(dest,'wb') as f:\n"
    "    while True:\n"
    "        b=r.read(1<<20)\n"
    "        if not b: break\n"
    "        h.update(b); f.write(b)\n"
    "got=h.hexdigest()\n"
    "print('FETCHED',dest,os.path.getsize(dest),got,flush=True)\n"
    "if sha and got!=sha: print('SHA_MISMATCH',got,sha,flush=True); sys.exit(3)\n"
)

_PROBE_SRC = (
    "import json,os,sys,time,urllib.request\n"
    "op=urllib.request.build_opener(urllib.request.ProxyHandler({}))\n"
    "base=os.environ.get('ENGINE_URL','http://127.0.0.1:8000')+'/v1'\n"
    "for _ in range(int(os.environ.get('ENGINE_WAIT','180'))):\n"
    "    try: op.open(base+'/models',timeout=3); break\n"
    "    except Exception: time.sleep(2)\n"
    "cases=json.loads(os.environ['PROMPTS_JSON'])['cases']; resp={}; toks=0; t0=time.monotonic()\n"
    "for c in cases:\n"
    "    body=json.dumps({'model':'m','messages':[{'role':'user','content':c['prompt']}],\n"
    "                     'temperature':0,'max_tokens':int(os.environ.get('MAX_TOKENS','256'))}).encode()\n"
    "    req=urllib.request.Request(base+'/chat/completions',data=body,method='POST',\n"
    "                               headers={'Content-Type':'application/json'})\n"
    "    try:\n"
    "        d=json.loads(op.open(req,timeout=180).read())\n"
    "        ans=d['choices'][0]['message']['content']\n"
    "        toks+=int(d.get('usage',{}).get('completion_tokens',0))\n"
    "    except Exception as exc:\n"
    "        ans=''; print('Q_ERR',c['id'],type(exc).__name__,flush=True)\n"
    "    resp[str(c['id'])]=[ans]; print('Q',c['id'],'->',ans[:60].replace(chr(10),' '),flush=True)\n"
    "dt=time.monotonic()-t0\n"
    "print(f'LLM_TIMING questions={len(cases)} completion_tokens={toks} secs={dt:.1f} "
    "tok_s={toks/max(dt,0.1):.1f}',flush=True)\n"
    "payload={'version':os.environ.get('PROMPT_SET',''),'scan_id':os.environ.get('SCAN_ID',''),\n"
    "         'bundle_id':os.environ.get('BUNDLE_ID',''),'engine_image':os.environ.get('ENGINE_IMAGE',''),\n"
    "         'metrics':{'questions':len(cases),'completion_tokens':toks,'secs':round(dt,1)},\n"
    "         'responses':resp}\n"
    "req=urllib.request.Request(os.environ['TESTING_URL']+'/llm/score',data=json.dumps(payload).encode(),\n"
    "                           method='POST',headers={'Authorization':'Bearer '+os.environ['MLSCAN_KEY'],\n"
    "                                                  'Content-Type':'application/json'})\n"
    "print('SCORE',op.open(req,timeout=120).read().decode(),flush=True)\n"
)


def make_llama_test_job(*, bundle_id: str, engine_image: str, model_url: str, model_sha256: str,
                        prompts: list, testing_url: str, api_key: str, prompt_set: str = "",
                        scan_id: str = "", namespace: str = NAMESPACE, gpu: bool = True,
                        runtime_class: str = "", cuda_visible_devices: str = "",
                        resources: dict | None = None, model_volume_size: str = "64Gi",
                        ttl_seconds: int = 3600, max_tokens: int = 256) -> dict:
    """Job теста bundle: fetcher (по presigned URL) -> engine (llama.cpp) -> probe (вопросы -> /llm/score).

    Движок обязан быть по digest (admission-политика); модель проверяется по sha256.
    """
    if "@sha256:" not in (engine_image or ""):
        raise ValueError("engine image должен быть по digest")
    if not model_url:
        raise ValueError("нужен presigned URL модели")
    res = resources or {"ram_gb": 32, "disk_gb": 40, "cpu": "4"}
    limits = {"memory": f"{int(res.get('ram_gb', 32))}Gi", "cpu": str(res.get("cpu", "4")),
              "ephemeral-storage": f"{int(res.get('disk_gb', 40))}Gi"}
    if gpu:
        limits["nvidia.com/gpu"] = 1
    engine_env = [{"name": "LLAMA_ARG_HOST", "value": "0.0.0.0"}]
    if gpu:
        engine_env.append({"name": "NVIDIA_VISIBLE_DEVICES", "value": "all"})
        if cuda_visible_devices:
            engine_env.append({"name": "CUDA_VISIBLE_DEVICES", "value": str(cuda_visible_devices)})
    # Числовой non-root (образы по умолчанию root -> kubelet отклоняет runAsNonRoot без runAsUser)
    uid = int(os.environ.get("MLSCAN_LLM_TEST_UID", "65532"))
    hardened = {"runAsNonRoot": True, "runAsUser": uid, "runAsGroup": uid,
                "allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}}
    engine_args = ["--model", "/model/model.gguf", "--host", "0.0.0.0", "--port", "8000",
                   "--ctx-size", "4096", "--n-gpu-layers", "99" if gpu else "0"]
    containers = [
        {"name": "engine", "image": engine_image, "env": engine_env, "args": engine_args,
         "ports": [{"name": "openai", "containerPort": 8000}],
         "resources": {"limits": limits},
         "securityContext": dict(hardened, readOnlyRootFilesystem=False),
         "volumeMounts": [{"name": "model", "mountPath": "/model", "readOnly": True}]
                         + ([{"name": "dev", "mountPath": "/dev"}] if gpu else []),
         "readinessProbe": {"httpGet": {"path": "/v1/models", "port": 8000},
                            "initialDelaySeconds": 10, "periodSeconds": 5, "failureThreshold": 60}},
        {"name": "probe", "image": "python:3.12-slim",
         "command": ["python", "-c", _PROBE_SRC],
         "env": [{"name": "PROMPTS_JSON", "value": json_dumps({"cases": prompts or []})},
                 {"name": "PROMPT_SET", "value": prompt_set},
                 {"name": "BUNDLE_ID", "value": bundle_id},
                 {"name": "SCAN_ID", "value": scan_id or ("bundle-test-" + bundle_id)},
                 {"name": "ENGINE_IMAGE", "value": engine_image},
                 {"name": "TESTING_URL", "value": testing_url},
                 {"name": "MLSCAN_KEY", "value": api_key},
                 {"name": "MAX_TOKENS", "value": str(int(max_tokens))}],
         "resources": {"limits": {"memory": "1Gi", "cpu": "1"}},
         "securityContext": dict(hardened, readOnlyRootFilesystem=False)},
    ]
    spec = {
        "backoffLimit": 0, "ttlSecondsAfterFinished": int(ttl_seconds),
        "template": {
            "metadata": {"labels": {"app": "mlscan-llm-test", "bundle": bundle_id[:40]}},
            "spec": {
                "automountServiceAccountToken": False,
                "restartPolicy": "Never",
                "securityContext": {"runAsNonRoot": True, "runAsUser": uid, "runAsGroup": uid,
                                    "fsGroup": uid, "seccompProfile": {"type": "RuntimeDefault"}},
                "initContainers": [{
                    "name": "model-fetcher", "image": "python:3.12-slim",
                    "command": ["python", "-c", _FETCH_SRC],
                    "env": [{"name": "FETCH_URL", "value": model_url},
                            {"name": "FETCH_SHA", "value": model_sha256},
                            {"name": "FETCH_DEST", "value": "/model/model.gguf"}],
                    "resources": {"limits": {"memory": "2Gi", "cpu": "1"}},
                    "securityContext": dict(hardened, readOnlyRootFilesystem=False),
                    "volumeMounts": [{"name": "model", "mountPath": "/model"}],
                }],
                "containers": containers,
                "volumes": [{"name": "model", "emptyDir": {"sizeLimit": model_volume_size}}]
                           + ([{"name": "dev", "hostPath": {"path": "/dev"}}] if gpu else []),
            },
        },
    }
    if runtime_class:
        spec["template"]["spec"]["runtimeClassName"] = runtime_class
    return {"apiVersion": "batch/v1", "kind": "Job",
            "metadata": {"name": f"mlscan-llm-test-{bundle_id[:24].replace('_', '-')}",
                         "namespace": namespace,
                         "labels": {"app": "mlscan-llm-test", "mlscan.io/bundle": bundle_id[:40]}},
            "spec": spec}


def json_dumps(obj) -> str:
    import json
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
