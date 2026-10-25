#!/usr/bin/env bash
# E2E H2/H3-lite (CPU, без Kata/eBPF): HF (прямая загрузка в initContainer) -> llama.cpp server ->
# 10 случайных вопросов из набора заказчика (questions_v9.xlsx) -> ответы -> /llm/score.
# Вопросы берутся из локального файла заказчика (в репозиторий НЕ коммитятся), subset грузится в БД.
#   bash tests/e2e/llama_cpp_e2e.sh [QUESTIONS_XLSX] [N]
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/../.." && pwd)"
XLSX="${1:-/home/col/Documents/Сибинтек/LLM_Sec/questions_v9.xlsx}"
N="${2:-10}"
NS_BUILD=mlscan-build; NS_T=mlscan-testing
IMG="ghcr.io/ggml-org/llama.cpp@sha256:1fa7f8f0ca663fdcf3203dc125a7e0b5c9e49c9ed054b049599666cd7e300eb0"
MODEL_URL="https://huggingface.co/ggml-org/gemma-3-270m-it-GGUF/resolve/main/gemma-3-270m-it-Q8_0.gguf"

[ -f "$XLSX" ] || { echo "нет файла вопросов: $XLSX"; exit 2; }
KEY="$(kubectl -n "$NS_T" get secret mlscan-keys -o jsonpath='{.data.MLSCAN_KEYS}' | base64 -d \
  | python3 -c 'import json,sys;d=json.load(sys.stdin);print([k for k,v in d.items() if v.get("roles")==["admin"]][0])')"

echo "== 1) subset N=$N из файла заказчика -> XLSX (только в БД, не в git) =="
python3 - "$ROOT" "$XLSX" "$N" <<'PY' > /tmp/e2e_hf_subset.json
import base64, io, json, os, random, sys
ROOT, XLSX, N = sys.argv[1], sys.argv[2], int(sys.argv[3])
sys.path.insert(0, os.path.join(ROOT, "deploy", "v3", "llm"))
sys.path.insert(0, os.path.join(ROOT, "tests", "v3"))
import xlsx, xlsx_write, promptset
rows = xlsx.read_xlsx_rows(XLSX, "questions_v9")
data = rows[1:]
random.seed(4242)
pick = random.sample(data, min(N, len(data)))
out = [xlsx_write.HEADERS] + [[str(c) for c in r[:5]] for r in pick]
xlsx_write.write_xlsx("/tmp/e2e_subset.xlsx", out)
cases = [{"id": p[0], "prompt": p[2], "reference": p[3], "criticality": int(p[4])} for p in pick]
print(json.dumps({"b64": base64.b64encode(open("/tmp/e2e_subset.xlsx","rb").read()).decode(),
                  "cases": cases}, ensure_ascii=False))
PY
B64="$(python3 -c "import json;print(json.load(open('/tmp/e2e_hf_subset.json'))['b64'])")"
VER="$(kubectl -n "$NS_T" exec -i deploy/mlscan-testing -- python3 - "$KEY" "$B64" <<'PY'
import json,sys,urllib.request
key,b64=sys.argv[1],sys.argv[2]
op=urllib.request.build_opener(urllib.request.ProxyHandler({}))
req=urllib.request.Request("http://127.0.0.1:8080/prompt-sets",data=json.dumps({"name":"hf-subset.xlsx","content_b64":b64}).encode(),
                           method="POST",headers={"Authorization":"Bearer "+key,"Content-Type":"application/json"})
print(json.loads(op.open(req,timeout=60).read())["version"])
PY
)"
echo "  активный набор: $VER"

echo "== 2) ConfigMap с вопросами (в кластере, не в git) =="
python3 -c "import json;c=json.load(open('/tmp/e2e_hf_subset.json'))['cases'];json.dump({'cases':c},open('/tmp/prompts.json','w'),ensure_ascii=False)"
kubectl -n "$NS_BUILD" create configmap mlscan-e2e-prompts --from-file=prompts.json=/tmp/prompts.json -o yaml --dry-run=client | kubectl apply -f - >/dev/null

echo "== 3) Job: init скачивает модель с HF -> llama.cpp server -> probe (10 вопросов) =="
cat > /tmp/llama_e2e_job.yaml <<Y
apiVersion: batch/v1
kind: Job
metadata: {name: llama-e2e, namespace: $NS_BUILD}
spec:
  backoffLimit: 0
  ttlSecondsAfterFinished: 3600
  template:
    spec:
      restartPolicy: Never
      securityContext: {runAsNonRoot: true, runAsUser: 65534, seccompProfile: {type: RuntimeDefault}}
      initContainers:
      - name: fetch-model
        image: curlimages/curl:8.10.1
        command: ["sh","-c","curl -sSL -o /model/model.gguf '$MODEL_URL' && ls -l /model/model.gguf"]
        volumeMounts: [{name: model, mountPath: /model}]
        securityContext: {allowPrivilegeEscalation: false, capabilities: {drop: ["ALL"]}}
      containers:
      - name: engine
        image: $IMG
        args: ["-m","/model/model.gguf","--host","127.0.0.1","--port","8000","-c","2048","-t","4","--jinja"]
        readinessProbe: {httpGet: {path: /v1/models, port: 8000}, initialDelaySeconds: 5, periodSeconds: 3, failureThreshold: 40}
        volumeMounts: [{name: model, mountPath: /model, readOnly: true}]
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
          import json,time,random,urllib.request
          op=urllib.request.build_opener(urllib.request.ProxyHandler({}))
          base="http://127.0.0.1:8000"
          for _ in range(120):
              try:
                  op.open(base+"/v1/models",timeout=3); break
              except Exception: time.sleep(2)
          cases=json.load(open("/prompts/prompts.json"))["cases"]
          resp={}
          for c in cases:
              body=json.dumps({"model":"m","messages":[{"role":"user","content":c["prompt"]}],
                               "temperature":0,"max_tokens":96}).encode()
              req=urllib.request.Request(base+"/v1/chat/completions",data=body,method="POST",
                                         headers={"Content-Type":"application/json"})
              try:
                  d=json.loads(op.open(req,timeout=120).read())
                  ans=d["choices"][0]["message"]["content"]
              except Exception as e:
                  ans=""
              resp[str(c["id"])]=[ans]
              print("Q",c["id"],"->",ans[:60].replace("\\n"," "),flush=True)
          import os
          key=os.environ["MLSCAN_KEY"]
          sreq=urllib.request.Request(os.environ["TESTING_URL"]+"/llm/score",
              data=json.dumps({"version":os.environ["PROMPT_SET"],"scan_id":"llama-cpp-e2e",
                               "responses":resp}).encode(),
              method="POST",headers={"Authorization":"Bearer "+key,"Content-Type":"application/json"})
          print("SCORE", op.open(sreq,timeout=60).read().decode(),flush=True)
      volumes:
      - {name: model, emptyDir: {sizeLimit: 4Gi}}
      - {name: prompts, configMap: {name: mlscan-e2e-prompts}}
Y
kubectl -n "$NS_BUILD" delete job llama-e2e --ignore-not-found >/dev/null 2>&1
kubectl apply -f /tmp/llama_e2e_job.yaml >/dev/null
echo "  job запущен; ожидание (модель + инференс)…"
for i in $(seq 1 60); do
  ph="$(kubectl -n "$NS_BUILD" get job llama-e2e -o jsonpath='{.status.conditions[0].type}' 2>/dev/null || true)"
  [ "$ph" = "Complete" ] || [ "$ph" = "Failed" ] && break
  sleep 10
done
kubectl -n "$NS_BUILD" logs job/llama-e2e -c probe 2>&1 | tail -14
