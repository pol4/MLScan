#!/usr/bin/env bash
# E2E H2-GPU: HF -> llama.cpp (CUDA, GPU) -> 10 случайных вопросов заказчика -> /llm/score.
# Требует: runtimeClassName nvidia (nvidia-container-runtime) и доступ к /dev (hostPath).
#   bash tests/e2e/llama_cpp_gpu_e2e.sh [QUESTIONS_XLSX] [N] [CUDA_VISIBLE_DEVICES]
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../.." && pwd)"
XLSX="${1:-/home/col/Documents/Сибинтек/LLM_Sec/questions_v9.xlsx}"; N="${2:-10}"; CUDA_IDX="${3:-1}"; GPU_COUNT="${4:-1}"
NS_BUILD=mlscan-build; NS_T=mlscan-testing
IMG="192.168.20.254:30003/mlscan/llama-cpp@sha256:d854233e9f043046f363953047ff518a9792b044cea1d53f86d299e88344cd5f"
MODEL_URL="https://huggingface.co/ggml-org/gemma-3-270m-it-GGUF/resolve/main/gemma-3-270m-it-Q8_0.gguf"
[ -f "$XLSX" ] || { echo "нет файла вопросов: $XLSX"; exit 2; }
KEY="$(kubectl -n "$NS_T" get secret mlscan-keys -o jsonpath='{.data.MLSCAN_KEYS}' | base64 -d \
  | python3 -c 'import json,sys;d=json.load(sys.stdin);print([k for k,v in d.items() if v.get("roles")==["admin"]][0])')"

python3 - "$ROOT" "$XLSX" "$N" <<'PY' > /tmp/gpu_subset.json
import base64, json, os, random, sys
ROOT, XLSX, N = sys.argv[1], sys.argv[2], int(sys.argv[3])
sys.path.insert(0, os.path.join(ROOT, "deploy", "v3", "llm")); sys.path.insert(0, os.path.join(ROOT, "tests", "v3"))
import xlsx, xlsx_write
rows = xlsx.read_xlsx_rows(XLSX, "questions_v9")[1:]
random.seed(4242); pick = random.sample(rows, min(N, len(rows)))
xlsx_write.write_xlsx("/tmp/gpu_subset.xlsx", [xlsx_write.HEADERS] + [[str(c) for c in r[:5]] for r in pick])
print(json.dumps({"b64": base64.b64encode(open("/tmp/gpu_subset.xlsx","rb").read()).decode(),
                  "cases": [{"id": p[0], "prompt": p[2]} for p in pick]}, ensure_ascii=False))
PY
B64="$(python3 -c "import json;print(json.load(open('/tmp/gpu_subset.json'))['b64'])")"
VER="$(kubectl -n "$NS_T" exec -i deploy/mlscan-testing -- python3 - "$KEY" "$B64" <<'PY'
import json,sys,urllib.request
key,b64=sys.argv[1],sys.argv[2]; op=urllib.request.build_opener(urllib.request.ProxyHandler({}))
req=urllib.request.Request("http://127.0.0.1:8080/prompt-sets",data=json.dumps({"name":"gpu-subset.xlsx","content_b64":b64}).encode(),
                           method="POST",headers={"Authorization":"Bearer "+key,"Content-Type":"application/json"})
print(json.loads(op.open(req,timeout=60).read())["version"])
PY
)"
echo "  prompt-set: $VER"
python3 -c "import json;json.dump({'cases':json.load(open('/tmp/gpu_subset.json'))['cases']},open('/tmp/gpu_prompts.json','w'),ensure_ascii=False)"
kubectl -n "$NS_BUILD" create configmap mlscan-gpu-prompts --from-file=prompts.json=/tmp/gpu_prompts.json -o yaml --dry-run=client | kubectl apply -f - >/dev/null

cat > /tmp/llama_gpu_job.yaml <<Y
apiVersion: batch/v1
kind: Job
metadata: {name: llama-gpu-e2e, namespace: $NS_BUILD}
spec:
  backoffLimit: 0
  ttlSecondsAfterFinished: 3600
  template:
    spec:
      restartPolicy: Never
      runtimeClassName: nvidia
      securityContext: {seccompProfile: {type: Unconfined}}
      containers:
      - name: engine
        image: $IMG
        resources: {limits: {"nvidia.com/gpu": ${GPU_COUNT:-1}}}
        args: ["-m","/models/gemma-3-270m-it-Q8_0.gguf","--host","127.0.0.1","--port","8000","-c","2048","-ngl","99","--jinja"]
        readinessProbe: {httpGet: {path: /v1/models, port: 8000}, initialDelaySeconds: 10, periodSeconds: 3, failureThreshold: 80}
        volumeMounts: [{name: models, mountPath: /models, readOnly: true}]
        securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: ["ALL"]}}
      - name: probe
        image: python:3.12-slim
        env:
        - {name: TESTING_URL, value: http://mlscan-testing.mlscan-testing.svc.cluster.local:8080}
        - {name: MLSCAN_KEY, value: "$KEY"}
        - {name: PROMPT_SET, value: "$VER"}
        volumeMounts: [{name: prompts, mountPath: /prompts, readOnly: true}]
        command: ["python","-c"]
        args:
        - |
          import json,time,urllib.request
          op=urllib.request.build_opener(urllib.request.ProxyHandler({}))
          base="http://127.0.0.1:8000"
          for _ in range(160):
              try: op.open(base+"/v1/models",timeout=3); break
              except Exception: time.sleep(2)
          cases=json.load(open("/prompts/prompts.json"))["cases"]; resp={}; toks=0
          t0=time.monotonic()
          for c in cases:
              body=json.dumps({"model":"m","messages":[{"role":"user","content":c["prompt"]}],
                               "temperature":0,"max_tokens":96}).encode()
              r=urllib.request.Request(base+"/v1/chat/completions",data=body,method="POST",
                                       headers={"Content-Type":"application/json"})
              try:
                  d=json.loads(op.open(r,timeout=180).read()); ans=d["choices"][0]["message"]["content"]
                  toks+=int(d.get("usage",{}).get("completion_tokens",0))
              except Exception: ans=""
              resp[str(c["id"])]=[ans]; print("Q",c["id"],"->",ans[:50].replace("\\n"," "),flush=True)
          dt=time.monotonic()-t0
          print(f"GPU_TIMING questions={len(cases)} completion_tokens={toks} secs={dt:.1f} tok_s={toks/max(dt,0.1):.1f}",flush=True)
          import os
          sreq=urllib.request.Request(os.environ["TESTING_URL"]+"/llm/score",
              data=json.dumps({"version":os.environ["PROMPT_SET"],"scan_id":"llama-gpu-e2e","responses":resp}).encode(),
              method="POST",headers={"Authorization":"Bearer "+os.environ["MLSCAN_KEY"],"Content-Type":"application/json"})
          print("SCORE",op.open(sreq,timeout=60).read().decode(),flush=True)
      volumes:
      - name: models
        persistentVolumeClaim: {claimName: llama-models}
      - {name: prompts, configMap: {name: mlscan-gpu-prompts}}
Y
kubectl -n "$NS_BUILD" delete job llama-gpu-e2e --ignore-not-found >/dev/null 2>&1
kubectl apply -f /tmp/llama_gpu_job.yaml >/dev/null; echo "  GPU job запущен"
