#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Единая тестовая среда Kata для LLM-инференса (v3, L1).

Формирует Job (один pod = одна микро-ВМ) с контейнерами: init `model-fetcher` (доставка модели из S3
в общий том), `engine` (customer-образ движка), `tetragon-agent` (in-guest eBPF), `probe-runner`
(запросы к OpenAI API на localhost). Проверяет достаточность ресурсов (GPU/RAM/диск) на LLM-пуле.
"""
from __future__ import annotations

import os
import sys

try:  # v4: движок как данные (образ/команда/ресурсы из EngineDescriptor)
    sys.path.insert(0, "/opt/v4")
    import engines.descriptor as _v4ed  # noqa: E402
except Exception:  # noqa: BLE001
    _v4ed = None

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
                  cuda_visible_devices: str = "", s3_env: dict | None = None,
                  s3_client_configmap: str = "mlscan-s3client") -> dict:
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
                        "env": [{"name": k, "value": v} for k, v in (s3_env or {}).items()],
                        "volumeMounts": ([{"name": "model", "mountPath": "/model"}]
                                         + ([{"name": "s3client", "mountPath": "/opt/s3", "readOnly": True}]
                                            if (model_key and s3_env) else [])),
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
                                + ([{"name": "s3client", "configMap": {"name": s3_client_configmap}}]
                                   if (model_key and s3_env) else [])
                                + ([{"name": "dev", "hostPath": {"path": "/dev"}}] if mount_dev else [])),
                },
            },
        },
    }


# --- N2: запускаемый job теста bundle (реальный движок + набор вопросов -> /llm/score) ----------
_FETCH_SRC = (
    "import hashlib,json,os,sys,urllib.request\n"
    "os.makedirs('/model',exist_ok=True)\n"
    "manifest=os.environ.get('FETCH_MANIFEST','')\n"
    "def s3get(s3,key,out):\n"
    "    os.makedirs(os.path.dirname(out),exist_ok=True)\n"
    "    st,hd,resp=s3.get_stream(key)\n"
    "    h=hashlib.sha256()\n"
    "    with open(out,'wb') as f:\n"
    "        try:\n"
    "            while True:\n"
    "                b=resp.read(1<<20)\n"
    "                if not b: break\n"
    "                h.update(b); f.write(b)\n"
    "        finally:\n"
    "            try: resp.close()\n"
    "            except Exception: pass\n"
    "    return h.hexdigest()\n"
    "if manifest:\n"
    "    files=json.loads(manifest)\n"
    "    s3=None\n"
    "    if any('key' in it for it in files):\n"
    "        sys.path.insert(0,'/opt/s3')\n"
    "        from s3client import S3\n"
    "        s3=S3(os.environ['S3_ENDPOINT'],os.environ['S3_ACCESS_KEY'],os.environ['S3_SECRET_KEY'],\n"
    "              region=os.environ.get('S3_REGION','garage'),bucket=os.environ['S3_BUCKET'],timeout=600)\n"
    "    op=urllib.request.build_opener(urllib.request.ProxyHandler({}))\n"
    "    for it in files:\n"
    "        out=os.path.join('/model',it['dest'])\n"
    "        if it.get('key'):\n"
    "            got=s3get(s3,it['key'],out)\n"
    "        else:\n"
    "            os.makedirs(os.path.dirname(out),exist_ok=True)\n"
    "            h=hashlib.sha256()\n"
    "            with op.open(it['url'],timeout=1800) as r, open(out,'wb') as f:\n"
    "                while True:\n"
    "                    b=r.read(1<<20)\n"
    "                    if not b: break\n"
    "                    h.update(b); f.write(b)\n"
    "            got=h.hexdigest()\n"
    "        print('FETCHED',out,os.path.getsize(out),got,flush=True)\n"
    "    sys.exit(0)\n"
    "dest=os.environ.get('FETCH_DEST','/model/model.gguf')\n"
    "sha=os.environ.get('FETCH_SHA','')\n"
    "key=os.environ.get('S3_KEY','')\n"
    "if key and os.path.exists('/opt/s3/s3client.py'):\n"
    "    sys.path.insert(0,'/opt/s3')\n"
    "    from s3client import S3\n"
    "    s3=S3(os.environ['S3_ENDPOINT'],os.environ['S3_ACCESS_KEY'],os.environ['S3_SECRET_KEY'],\n"
    "          region=os.environ.get('S3_REGION','garage'),bucket=os.environ['S3_BUCKET'],timeout=600)\n"
    "    got=s3get(s3,key,dest)\n"
    "else:\n"
    "    h=hashlib.sha256(); op=urllib.request.build_opener(urllib.request.ProxyHandler({}))\n"
    "    with op.open(os.environ['FETCH_URL'],timeout=1800) as r, open(dest,'wb') as f:\n"
    "        while True:\n"
    "            b=r.read(1<<20)\n"
    "            if not b: break\n"
    "            h.update(b); f.write(b)\n"
    "    got=h.hexdigest()\n"
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
    "tu=os.environ.get('TESTPACK_URL','')\n"
    "tp=json.loads(op.open(tu,timeout=60).read()) if tu else None\n"
    "pf=os.environ.get('PROMPTS_FILE','')\n"
    "pu=os.environ.get('PROMPTS_URL','')\n"
    "cases=(tp['cases'] if tp else\n"
    "       (json.loads(op.open(pu,timeout=60).read()) if pu else\n"
    "        (json.load(open(pf)) if pf else json.loads(os.environ['PROMPTS_JSON'])))['cases'])\n"
    "resp={}; toks=0; ok=0; t0=time.monotonic()\n"
    "for c in cases:\n"
    "    body=json.dumps({'model':'m','messages':[{'role':'user','content':c['prompt']}],\n"
    "                     'temperature':0,'max_tokens':int(os.environ.get('MAX_TOKENS','256'))}).encode()\n"
    "    req=urllib.request.Request(base+'/chat/completions',data=body,method='POST',\n"
    "                               headers={'Content-Type':'application/json'})\n"
    "    try:\n"
    "        d=json.loads(op.open(req,timeout=180).read())\n"
    "        ans=d['choices'][0]['message']['content']\n"
    "        toks+=int(d.get('usage',{}).get('completion_tokens',0))\n"
    "        ok+=1\n"
    "    except Exception as exc:\n"
    "        ans=''; print('Q_ERR',c['id'],type(exc).__name__,flush=True)\n"
    "    resp[str(c['id'])]=[ans]; print('Q',c['id'],'->',ans[:60].replace(chr(10),' '),flush=True)\n"
    "dt=time.monotonic()-t0\n"
    "if not ok: print('LLM_NO_ANSWERS',flush=True); sys.exit(4)\n"
    "print(f'LLM_TIMING questions={len(cases)} completion_tokens={toks} secs={dt:.1f} "
    "tok_s={toks/max(dt,0.1):.1f}',flush=True)\n"
    "payload={'version':os.environ.get('PROMPT_SET',''),'scan_id':os.environ.get('SCAN_ID',''),\n"
    "         'bundle_id':os.environ.get('BUNDLE_ID',''),'engine_image':os.environ.get('ENGINE_IMAGE',''),\n"
    "         'testpack':(json.loads(os.environ['TESTPACK_META']) if os.environ.get('TESTPACK_META') else None),\n"
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
                        ttl_seconds: int = 3600, max_tokens: int = 256,
                        ebpf_agent: bool = False, ebpf_configmap: str = "mlscan-ebpf-agent",
                        ebpf_image: str = "", model_key: str = "", s3_env: dict | None = None,
                        s3_client_configmap: str = "mlscan-s3client",
                        model_files: list | None = None, prompts_configmap: str = "",
                        prompts_url: str = "", sgl_shim: bool = False,
                        testpack_url: str = "", testpack_meta: str = "",
                        engine_descriptor: dict | None = None, deception: bool = True) -> dict:
    """Job теста bundle: fetcher (по presigned URL) -> engine (llama.cpp) -> probe (вопросы -> /llm/score).

    Движок обязан быть по digest (admission-политика); модель проверяется по sha256.
    """
    if "@sha256:" not in (engine_image or ""):
        raise ValueError("engine image должен быть по digest")
    if not model_url and not model_files:
        raise ValueError("нужен presigned URL или манифест файлов модели")
    # GPU без device-plugin: прямая CDI-инъекция через annotation (containerd enable_cdi).
    # MLSCAN_GPU_MODE=cdi (по умолчанию) -> аннотация cdi.k8s.io/mlscan-gpu: nvidia.com/gpu=<uuid|index>
    gpu_mode = os.environ.get("MLSCAN_GPU_MODE", "cdi")   # cdi | hostdev | device-plugin(limits)
    gpu_uuid = os.environ.get("MLSCAN_GPU_UUID", "")
    gpu_index = os.environ.get("MLSCAN_GPU_INDEX", "0")
    gpu_cdi_devices = os.environ.get("MLSCAN_GPU_CDI_DEVICES", "nvidia.com/gpu=0")
    res = resources or {"ram_gb": 32, "disk_gb": 40, "cpu": "4"}
    limits = {"memory": f"{int(res.get('ram_gb', 32))}Gi", "cpu": str(res.get("cpu", "4")),
              "ephemeral-storage": f"{int(res.get('disk_gb', 40))}Gi"}
    if gpu and gpu_mode == "device-plugin":
        limits["nvidia.com/gpu"] = 1
    engine_env = [{"name": "LLAMA_ARG_HOST", "value": "0.0.0.0"},
                  # числовой UID без записи в /etc/passwd -> torch.getpass.getuser() падает
                  {"name": "USER", "value": "mlscan"}, {"name": "LOGNAME", "value": "mlscan"},
                  {"name": "HOME", "value": "/tmp"},
                  {"name": "TORCHINDUCTOR_CACHE_DIR", "value": "/tmp/torchinductor"},
                  {"name": "TRITON_CACHE_DIR", "value": "/tmp/triton"},
                  {"name": "XDG_CACHE_HOME", "value": "/tmp/.cache"}]
    if gpu:
        engine_env.append({"name": "NVIDIA_VISIBLE_DEVICES", "value": gpu_uuid or "all"})
        if gpu_mode == "hostdev":
            engine_env.append({"name": "CUDA_VISIBLE_DEVICES", "value": gpu_index})
        if cuda_visible_devices:
            engine_env.append({"name": "CUDA_VISIBLE_DEVICES", "value": str(cuda_visible_devices)})
    # Числовой non-root (образы по умолчанию root -> kubelet отклоняет runAsNonRoot без runAsUser)
    uid = int(os.environ.get("MLSCAN_LLM_TEST_UID", "65532"))
    hardened = {"runAsNonRoot": True, "runAsUser": uid, "runAsGroup": uid,
                "allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}}
    # Ф5: ловушки (honeypot-секреты) монтируются и на инференс-путь (HOME остаётся writable)
    if deception:
        engine_env += [
            {"name": "AWS_SHARED_CREDENTIALS_FILE", "value": "/deception/.aws/credentials"},
            {"name": "AWS_CONFIG_FILE", "value": "/deception/.aws/config"},
            {"name": "KUBECONFIG", "value": "/deception/.kube/config"}]
    eng_l = (engine_image or "").lower()
    model_path = "/model" if model_files else "/model/model.gguf"
    if "sglang" in eng_l:
        engine_command = ["python3", "-m", "sglang.launch_server", "--model-path", model_path,
                          "--host", "0.0.0.0", "--port", "8000", "--context-length", "4096",
                          "--served-model-name", "m", "--disable-cuda-graph"]
        # sm_75 (Turing): sgl_kernel собран без sm_75 -> native/torch fallbacks.
        if "sm75" in eng_l or sgl_shim:
            engine_command += ["--attention-backend", "torch_native",
                               "--sampling-backend", "pytorch", "--dtype", "float16"]
        engine_args = []
    elif "vllm" in eng_l:
        engine_command = ["vllm", "serve", model_path, "--host", "0.0.0.0", "--port", "8000",
                          "--max-model-len", "4096", "--gpu-memory-utilization", "0.90",
                          "--swap-space", "0", "--served-model-name", "m"]
        engine_args = []
    else:
        engine_command = None
        engine_args = ["--model", model_path, "--host", "0.0.0.0", "--port", "8000",
                       "--ctx-size", "4096", "--n-gpu-layers", "99" if gpu else "0"]
    if sgl_shim:
        engine_env = engine_env + [{"name": "PYTHONPATH", "value": "/opt/sgl-sm75"}]
    _engine_c = {"name": "engine", "image": engine_image, "env": engine_env,
                 "ports": [{"name": "openai", "containerPort": 8000}],
                 "resources": {"limits": limits},
                 "securityContext": dict(hardened, readOnlyRootFilesystem=False),
                 "volumeMounts": [{"name": "model", "mountPath": "/model", "readOnly": True}]
                                 + ([{"name": "sgl-shim", "mountPath": "/opt/sgl-sm75", "readOnly": True}]
                                    if sgl_shim else [])
                                 + ([{"name": "deception", "mountPath": "/deception", "readOnly": True},
                                     {"name": "deception-aws", "mountPath": "/deception/.aws", "readOnly": True},
                                     {"name": "deception-ssh", "mountPath": "/deception/.ssh", "readOnly": True},
                                     {"name": "deception-kube", "mountPath": "/deception/.kube", "readOnly": True}]
                                    if deception else [])
                                 + ([{"name": "dev", "mountPath": "/dev"},
                                     {"name": "cudalibs", "mountPath": "/usr/lib/x86_64-linux-gnu", "readOnly": True}]
                                    if (gpu and gpu_mode == "hostdev") else []),
                 "readinessProbe": {"httpGet": {"path": "/v1/models", "port": 8000},
                                    "initialDelaySeconds": 10, "periodSeconds": 5, "failureThreshold": 60}}
    if engine_command:
        _engine_c["command"] = engine_command
    else:
        _engine_c["args"] = engine_args
    # v4 (E4): образ/команда/ресурсы из EngineDescriptor (аддитивно, при наличии)
    if engine_descriptor and _v4ed is not None:
        try:
            _d = _v4ed.EngineDescriptor.from_dict(engine_descriptor)
            _r = _v4ed.to_k8s_resources(_d)
            if _r.get("limits"):
                _engine_c["resources"] = {"limits": {**(_engine_c["resources"].get("limits") or {}),
                                                     **_r["limits"]}}
            _cmd = _v4ed.render_start(_d, model_path)
            if _cmd:
                _engine_c.pop("args", None)
                _engine_c["command"] = _cmd
        except Exception:  # noqa: BLE001
            pass
    containers = [
        _engine_c,
        {"name": "probe", "image": "python:3.12-slim",
         "command": ["python", "-c", _PROBE_SRC],
         "securityContext": dict(hardened, readOnlyRootFilesystem=False),
         "volumeMounts": ([{"name": "prompts", "mountPath": "/prompts", "readOnly": True}]
                          if prompts_configmap else []),
         "env": (([{"name": "TESTPACK_URL", "value": testpack_url},
                   {"name": "TESTPACK_META", "value": testpack_meta}] if testpack_url else
                  ([{"name": "PROMPTS_URL", "value": prompts_url}] if prompts_url else
                   ([{"name": "PROMPTS_FILE", "value": "/prompts/prompts.json"}] if prompts_configmap else
                    [{"name": "PROMPTS_JSON", "value": json_dumps({"cases": prompts or []})}])))
                 + [{"name": "PROMPT_SET", "value": prompt_set},
                 {"name": "BUNDLE_ID", "value": bundle_id},
                 {"name": "SCAN_ID", "value": scan_id or ("bundle-test-" + bundle_id)},
                 {"name": "ENGINE_IMAGE", "value": engine_image},
                 {"name": "TESTING_URL", "value": testing_url},
                 {"name": "MLSCAN_KEY", "value": api_key},
                 {"name": "MAX_TOKENS", "value": str(int(max_tokens))}]),
         "resources": {"limits": {"memory": "1Gi", "cpu": "1"}},
         "securityContext": dict(hardened, readOnlyRootFilesystem=False)},
    ]
    if ebpf_agent:      # B1: наблюдение ядерных событий инференса внутри гостевой ВМ
        # B1: образ сенсора (digest-pinned) предпочтительнее ConfigMap; при отсутствии — python + ConfigMap
        _ebpf_image = ebpf_image or os.environ.get("EBPF_AGENT_IMAGE", "")
        containers.append({
            "name": "ebpf-agent", "image": _ebpf_image or "python:3.12-slim",
            "command": ["python", "/opt/ebpf/ebpf_agent.py", "--duration", str(int(ttl_seconds) - 30),
                        "--post", testing_url, "--key", api_key,
                        "--scan-id", scan_id or ("bundle-test-" + bundle_id), "--nonce", "",
                        "--trigger-shell"],
            "env": ([{"name": "EBPF_DUMP_SLOTS", "value": "1"}, {"name": "EBPF_DUMP_RINGS", "value": "1"}]
                    if os.environ.get("MLSCAN_EBPF_DEBUG") == "1" else []),
            # в этой сборке Kata eBPF доступен только root-в-госте (non-root даёт EPERM даже с CAP_BPF):
            # агент — наш доверенный код, движок остаётся non-root; под изолирован в микро-ВМ.
            "securityContext": {"runAsNonRoot": False, "runAsUser": 0,
                                "allowPrivilegeEscalation": False,
                                "capabilities": {"drop": ["ALL"], "add": ["BPF", "PERFMON"]}},
            "volumeMounts": ([] if _ebpf_image else
                             [{"name": "ebpf", "mountPath": "/opt/ebpf", "readOnly": True}]),
            "resources": {"limits": {"memory": "512Mi", "cpu": "1"}}})
    annotations = {}
    if gpu and gpu_mode == "cdi":
        annotations["cdi.k8s.io/mlscan-gpu"] = gpu_cdi_devices    # containerd сам инжектит устройства
    spec = {
        "backoffLimit": 0, "ttlSecondsAfterFinished": int(ttl_seconds),
        "template": {
            "metadata": ({"labels": {"app": "mlscan-llm-test", "bundle": bundle_id[:40]},
                          "annotations": annotations} if annotations else
                         {"labels": {"app": "mlscan-llm-test", "bundle": bundle_id[:40]}}),
            "spec": {
                "automountServiceAccountToken": False,
                "restartPolicy": "Never",
                "imagePullSecrets": [{"name": "harbor-pull"}],
                "securityContext": ({"fsGroup": uid, "seccompProfile": {"type": "RuntimeDefault"}}
                                    if ebpf_agent else
                                    {"runAsNonRoot": True, "runAsUser": uid, "runAsGroup": uid,
                                     "fsGroup": uid, "seccompProfile": {"type": "RuntimeDefault"}}),
                "initContainers": [{
                    "name": "model-fetcher", "image": "python:3.12-slim",
                    "command": ["python", "-c", _FETCH_SRC],
                    "env": (([{"name": "FETCH_MANIFEST", "value": json_dumps(model_files)}] if model_files else
                             [{"name": "FETCH_URL", "value": model_url},
                              {"name": "FETCH_SHA", "value": model_sha256},
                              {"name": "FETCH_DEST", "value": "/model/model.gguf"},
                              {"name": "S3_KEY", "value": model_key}])
                            + [{"name": k, "value": v} for k, v in (s3_env or {}).items()]),
                    "resources": {"limits": {"memory": "2Gi", "cpu": "1"}},
                    "securityContext": dict(hardened, readOnlyRootFilesystem=False),
                    "volumeMounts": ([{"name": "model", "mountPath": "/model"}]
                                     + ([{"name": "s3client", "mountPath": "/opt/s3", "readOnly": True}]
                                        if ((model_key and s3_env) or (model_files and s3_env)) else [])),
                }],
                "containers": containers,
                "volumes": ([{"name": "model", "emptyDir": {"sizeLimit": model_volume_size}}]
                            + ([{"name": "s3client", "configMap": {"name": s3_client_configmap}}]
                               if ((model_key and s3_env) or (model_files and s3_env)) else [])) 
                           + ([{"name": "prompts", "configMap": {"name": prompts_configmap}}]
                              if prompts_configmap else [])
                           + ([{"name": "sgl-shim", "configMap": {"name": "sgl-shim"}}]
                              if sgl_shim else [])
                           + ([{"name": "deception", "configMap": {"name": "mlscan-deception"}},
                               {"name": "deception-aws", "configMap": {"name": "mlscan-deception-aws"}},
                               {"name": "deception-ssh", "configMap": {"name": "mlscan-deception-ssh"}},
                               {"name": "deception-kube", "configMap": {"name": "mlscan-deception-kube"}}]
                              if deception else [])
                           + ([{"name": "dev", "hostPath": {"path": "/dev"}}]
                              if (gpu and gpu_mode == "hostdev") else [])
                           + ([{"name": "cudalibs", "hostPath": {"path": "/usr/lib/x86_64-linux-gnu"}}]
                              if (gpu and gpu_mode == "hostdev") else [])
                           + ([{"name": "ebpf", "configMap": {"name": ebpf_configmap}}]
                              if (ebpf_agent and not os.environ.get("EBPF_AGENT_IMAGE")) else []),
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
