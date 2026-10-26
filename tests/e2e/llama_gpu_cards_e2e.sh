#!/usr/bin/env bash
# E2E: (A) небольшая модель на ВТОРОЙ карте RTX 4000; (B) модель побольше — инференс на ДВУХ картах.
# Требует: device-plugin (nvidia.com/gpu=2) + runtimeClassName nvidia; модели — в PVC llama-models.
#   bash tests/e2e/llama_gpu_cards_e2e.sh [QUESTIONS_XLSX] [N]
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../.." && pwd)"
XLSX="${1:-/home/col/Documents/Сибинтек/LLM_Sec/questions_v9.xlsx}"; N="${2:-10}"
NS=mlscan-build; NST=mlscan-testing
IMG="ghcr.io/ggml-org/llama.cpp:server-cuda"
KEY="$(kubectl -n "$NST" get secret mlscan-keys -o jsonpath='{.data.MLSCAN_KEYS}' | base64 -d \
  | python3 -c 'import json,sys;d=json.load(sys.stdin);print([k for k,v in d.items() if v.get("roles")==["admin"]][0])')"
AVAIL="$(kubectl get node -o jsonpath='{.items[0].status.allocatable.nvidia\.com/gpu}')"
echo "== nvidia.com/gpu allocatable: $AVAIL"; [ "$AVAIL" = "2" ] || { echo "ожидалось 2 GPU"; exit 2; }

wait_job() { local n="$1"; for i in $(seq 1 40); do
  ph=$(kubectl -n "$NS" get job "$n" -o jsonpath='{.status.conditions[0].type}' 2>/dev/null)
  case "$ph" in Complete|SuccessCriteriaMet|Failed) break;; esac; sleep 15; done; echo "  job $n: $ph"; }

devices_pod() { # name gpu_count cuda_env
  local n="$1" g="$2" c="$3"
  kubectl -n "$NS" delete pod "$n" --ignore-not-found >/dev/null 2>&1
  local envjson="[]"; [ -n "$c" ] && envjson="[{\"name\":\"CUDA_VISIBLE_DEVICES\",\"value\":\"$c\"}]"
  local ov="{\"spec\":{\"runtimeClassName\":\"nvidia\",\"containers\":[{\"name\":\"devs\",\"image\":\"$IMG\",\"command\":[\"/app/llama-server\",\"--list-devices\"],\"env\":$envjson,\"resources\":{\"limits\":{\"nvidia.com/gpu\":$g}}}]}}"
  kubectl -n "$NS" run "$n" --image="$IMG" --restart=Never --overrides="$ov" >/dev/null 2>&1
  for i in $(seq 1 15); do ph=$(kubectl -n "$NS" get pod "$n" -o jsonpath='{.status.phase}' 2>/dev/null); case "$ph" in Succeeded|Failed) break;; esac; sleep 8; done
  echo "  devices($n):"; kubectl -n "$NS" logs "$n" 2>&1 | grep -iE "Available devices|CUDA" | head -4
  kubectl -n "$NS" delete pod "$n" --ignore-not-found >/dev/null 2>&1
}

# --- набор вопросов (10 случайных из файла заказчика) -> /prompt-sets -> ConfigMap
python3 - "$ROOT" "$XLSX" "$N" <<'PY' > /tmp/cards_subset.json
import base64, json, os, random, sys
ROOT, XLSX, N = sys.argv[1], sys.argv[2], int(sys.argv[3])
sys.path.insert(0, os.path.join(ROOT, "deploy", "v3", "llm")); sys.path.insert(0, os.path.join(ROOT, "tests", "v3"))
import xlsx, xlsx_write
rows = xlsx.read_xlsx_rows(XLSX, "questions_v9")[1:]
random.seed(4242); pick = random.sample(rows, min(N, len(rows)))
xlsx_write.write_xlsx("/tmp/cards_subset.xlsx", [xlsx_write.HEADERS] + [[str(c) for c in r[:5]] for r in pick])
print(json.dumps({"b64": base64.b64encode(open("/tmp/cards_subset.xlsx","rb").read()).decode(),
                  "cases": [{"id": p[0], "prompt": p[2]} for p in pick]}, ensure_ascii=False))
PY
B64="$(python3 -c "import json;print(json.load(open('/tmp/cards_subset.json'))['b64'])")"
VER="$(kubectl -n "$NST" exec -i deploy/mlscan-testing -- python3 - "$KEY" "$B64" <<'PY'
import json,sys,urllib.request
key,b64=sys.argv[1],sys.argv[2]; op=urllib.request.build_opener(urllib.request.ProxyHandler({}))
r=urllib.request.Request("http://127.0.0.1:8080/prompt-sets",data=json.dumps({"name":"cards.xlsx","content_b64":b64}).encode(),
                         method="POST",headers={"Authorization":"Bearer "+key,"Content-Type":"application/json"})
print(json.loads(op.open(r,timeout=60).read())["version"])
PY
)"
echo "  prompt-set: $VER"
python3 -c "import json;json.dump({'cases':json.load(open('/tmp/cards_subset.json'))['cases']},open('/tmp/cards_prompts.json','w'),ensure_ascii=False)"
kubectl -n "$NS" create configmap mlscan-gpu-prompts --from-file=prompts.json=/tmp/cards_prompts.json -o yaml --dry-run=client | kubectl apply -f - >/dev/null

job_yaml() { # file name model gpus env_line args_extra
  local f="$1" n="$2" model="$3" g="$4" envl="$5" ax="$6"
  cat > "$f" <<Y
apiVersion: batch/v1
kind: Job
metadata: {name: $n, namespace: $NS}
spec:
  backoffLimit: 0
  ttlSecondsAfterFinished: 1
  template:
    spec:
      restartPolicy: Never
      runtimeClassName: nvidia
      securityContext: {seccompProfile: {type: Unconfined}}
      containers:
      - name: engine
        image: $IMG
        resources: {limits: {"nvidia.com/gpu": $g}}
$envl
        args: ["-m","/models/$model","--host","127.0.0.1","--port","8000","-c","2048","-ngl","99","--jinja"$ax]
        readinessProbe: {httpGet: {path: /v1/models, port: 8000}, initialDelaySeconds: 10, periodSeconds: 3, failureThreshold: 100}
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
          import json,os,time,urllib.request
          op=urllib.request.build_opener(urllib.request.ProxyHandler({}))
          base="http://127.0.0.1:8000"
          for _ in range(160):
              try: op.open(base+"/v1/models",timeout=3); break
              except Exception: time.sleep(2)
          cases=json.load(open("/prompts/prompts.json"))["cases"]; resp={}; toks=0; t0=time.monotonic()
          for c in cases:
              body=json.dumps({"model":"m","messages":[{"role":"user","content":c["prompt"]}],
                               "temperature":0,"max_tokens":96}).encode()
              r=urllib.request.Request(base+"/v1/chat/completions",data=body,method="POST",
                                       headers={"Content-Type":"application/json"})
              try:
                  d=json.loads(op.open(r,timeout=240).read()); ans=d["choices"][0]["message"]["content"]
                  toks+=int(d.get("usage",{}).get("completion_tokens",0))
              except Exception: ans=""
              resp[str(c["id"])]=[ans]
          dt=time.monotonic()-t0
          print(f"TIMING questions={len(cases)} tokens={toks} secs={dt:.1f} tok_s={toks/max(dt,0.1):.1f}",flush=True)
          sreq=urllib.request.Request(os.environ["TESTING_URL"]+"/llm/score",
              data=json.dumps({"version":os.environ["PROMPT_SET"],"scan_id":"$n","responses":resp}).encode(),
              method="POST",headers={"Authorization":"Bearer "+os.environ["MLSCAN_KEY"],"Content-Type":"application/json"})
          print("SCORE",op.open(sreq,timeout=60).read().decode(),flush=True)
      volumes:
      - name: models
        persistentVolumeClaim: {claimName: llama-models}
      - {name: prompts, configMap: {name: mlscan-gpu-prompts}}
Y
  kubectl -n "$NS" delete job "$n" --ignore-not-found >/dev/null 2>&1
  kubectl apply -f "$f" >/dev/null
}

echo "== A) небольшая модель (gemma-3-270m) на ВТОРОЙ карте (CUDA_VISIBLE_DEVICES=1) =="
devices_pod llama-dev-a 2 "1"
job_yaml /tmp/cards-a.yaml llama-cards-a gemma-3-270m-it-Q8_0.gguf 2 '        env: [{name: CUDA_VISIBLE_DEVICES, value: "1"}]' ''
wait_job llama-cards-a
kubectl -n "$NS" logs job/llama-cards-a -c engine 2>&1 | grep -iE "eval time" | tail -2
kubectl -n "$NS" logs job/llama-cards-a -c probe 2>&1 | tail -2
kubectl -n "$NS" delete pods -l job-name=llama-cards-a --ignore-not-found >/dev/null 2>&1

echo "== B) модель побольше (Qwen2.5-3B Q4) на ДВУХ картах (tensor-split 1,1) =="
devices_pod llama-dev-b 2 ""
job_yaml /tmp/cards-b.yaml llama-cards-b Qwen2.5-3B-Instruct-Q4_K_M.gguf 2 '' ',"--tensor-split","1,1","--split-mode","layer"'
wait_job llama-cards-b
kubectl -n "$NS" logs job/llama-cards-b -c engine 2>&1 | grep -iE "buffer size|offloading|eval time" | tail -6
kubectl -n "$NS" logs job/llama-cards-b -c probe 2>&1 | tail -2
kubectl -n "$NS" delete pods -l job-name=llama-cards-b --ignore-not-found >/dev/null 2>&1
echo "DONE"
