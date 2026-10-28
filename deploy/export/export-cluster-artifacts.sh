#!/usr/bin/env bash
# Экспорт артефактов стенда MLScan из кластера (перед переустановкой Kubernetes).
#
# Собирает в OUT (по умолчанию /tmp/mlscan-cluster-export):
#   manifests/ — манифесты по нашим namespace (deploy/sts/ds/cronjob/svc/cm/pvc/netpol/ingress/sa/role)
#   secrets/   — список секретов; с --with-secrets — декодированные значения (файл 0600)
#   db/        — дамп Postgres (schema-only и full) + список таблиц и число строк
#   s3/        — список объектов Garage (данные не выгружаются: пере-засев из HF/через UI)
#   images/    — список образов с digest + tar локально собранных образов
#   node/      — конфиги узла, которые мы меняли (kata, containerd-template, digest песочницы)
#   cluster/   — Kyverno-политики, StorageClass/RuntimeClass, namespace, CRD, addons, каталог реестра
#   repo/      — git-состояние репозитория
#
# Использование: bash deploy/export/export-cluster-artifacts.sh [--with-secrets] [OUT_DIR]
set -uo pipefail
CTX="${MLSCAN_KUBE_CONTEXT:-microk8s}"
NODE="${MLSCAN_NODE_SSH:-col@rtx-cluster}"
WITH_SECRETS=0; OUT=""
for a in "$@"; do case "$a" in --with-secrets) WITH_SECRETS=1 ;; *) OUT="$a" ;; esac; done
OUT="${OUT:-/tmp/mlscan-cluster-export}"
NS_LIST="mlscan-analytics mlscan-build mlscan-data mlscan-ingress mlscan-integrations mlscan-monitoring mlscan-ops mlscan-sandbox mlscan-testing mlscan-v3-data"
mkdir -p "$OUT"/{manifests,secrets,db,s3,images,node,cluster,repo}
echo "[export] OUT=$OUT"

echo "[export] 1) манифесты"
for ns in $NS_LIST; do
  for kind in deploy sts ds cronjob svc cm pvc netpol ingress sa role rolebinding; do
    kubectl --context "$CTX" -n "$ns" get "$kind" -o yaml > "$OUT/manifests/$ns-$kind.yaml" 2>/dev/null \
      || rm -f "$OUT/manifests/$ns-$kind.yaml"
  done
done
kubectl --context "$CTX" get clusterrole,clusterrolebinding -o yaml > "$OUT/manifests/cluster-rbac.yaml" 2>/dev/null || true

echo "[export] 2) секреты"
kubectl --context "$CTX" get secrets -A -o json > "$OUT/secrets/secret-list.json" 2>/dev/null
if [ "$WITH_SECRETS" = "1" ]; then
  kubectl --context "$CTX" get secrets -A -o json > "$OUT/secrets/_raw.json" 2>/dev/null
  python3 - "$OUT/secrets/_raw.json" "$OUT/secrets/secrets-decoded.json" <<'PY'
import base64, json, os, sys
src, dst = sys.argv[1], sys.argv[2]
out = {}
try:
    d = json.load(open(src))
except Exception:
    d = {"items": []}
for it in d.get("items", []):
    ns, name = it["metadata"]["namespace"], it["metadata"]["name"]
    if not ns.startswith("mlscan"):
        continue
    out.setdefault(ns, {})[name] = {k: base64.b64decode(v).decode("utf-8", "replace")
                                     for k, v in (it.get("data") or {}).items()}
open(dst, "w").write(json.dumps(out, ensure_ascii=False, indent=2))
os.chmod(dst, 0o600)
print("  секретов:", sum(len(v) for v in out.values()))
PY
  rm -f "$OUT/secrets/_raw.json"
else
  echo "  (значения не выгружались: --with-secrets выключен)"
fi

echo "[export] 3) база данных"
PODP="$(kubectl --context "$CTX" -n mlscan-data get pods -l app=postgres -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo postgres-0)"
kubectl --context "$CTX" -n mlscan-data exec "$PODP" -- pg_dump -U mlscan -d mlscan --no-owner --schema-only > "$OUT/db/schema.sql" 2>/dev/null || true
kubectl --context "$CTX" -n mlscan-data exec "$PODP" -- pg_dump -U mlscan -d mlscan --no-owner > "$OUT/db/full.sql" 2>/dev/null || true
kubectl --context "$CTX" -n mlscan-data exec "$PODP" -- psql -U mlscan -d mlscan -c "\dt+" > "$OUT/db/tables.txt" 2>/dev/null || true
: > "$OUT/db/rowcounts.txt"
for t in artifacts scans bundles bundle_verdicts bundle_verdict_chain gate_decisions hf_downloads \
         hf_egress_log hf_quotas hf_tokens scan_tokens registry_images llm_prompts prompt_sets bundle_tests; do
  printf "%-24s " "$t" >> "$OUT/db/rowcounts.txt"
  kubectl --context "$CTX" -n mlscan-data exec "$PODP" -- psql -U mlscan -d mlscan -tAc "SELECT count(*) FROM $t" \
    2>/dev/null >> "$OUT/db/rowcounts.txt || echo "(нет)" >> "$OUT/db/rowcounts.txt"
done

echo "[export] 4) S3 (Garage): список объектов"
kubectl --context "$CTX" -n mlscan-testing exec deploy/mlscan-testing -- python3 -c "
import json, os, sys
sys.path.insert(0, '/opt/s3')
from s3client import S3
s3 = S3(os.environ['S3_ENDPOINT'], os.environ['S3_ACCESS_KEY'], os.environ['S3_SECRET_KEY'],
        region='garage', bucket=os.environ['S3_BUCKET'], timeout=60)
keys = []
for name in ('list_prefix', 'list_objects', 'list'):
    fn = getattr(s3, name, None)
    if fn:
        try:
            keys = fn('') or []
            break
        except Exception:
            keys = []
print(json.dumps({'bucket': os.environ.get('S3_BUCKET'), 'count': len(keys), 'objects': keys[:5000]}))
" > "$OUT/s3/objects.json" 2>/dev/null || echo '{"note":"не удалось получить список (см. s3client)"}' > "$OUT/s3/objects.json"

echo "[export] 5) образы"
"${SSH[@]}" 'sudo /snap/bin/microk8s ctr images ls -q 2>/dev/null | grep -E "mlscan|ggml|tetragon"' > "$OUT/images/list.txt" 2>/dev/null || true
"${SSH[@]}" 'curl -s -m 10 http://localhost:32000/v2/_catalog' > "$OUT/cluster/registry-catalog.json" 2>/dev/null || true
for img in mlscan-sandbox mlscan/ebpf-agent; do
  safe="$(echo "$img" | tr '/' '_')"
  for tag in latest v1 v2; do
    if "${SSH[@]}" "sudo /snap/bin/microk8s ctr images export /tmp/${safe}.tar 'localhost:32000/$img:$tag'" >/dev/null 2>&1; then
      if scp -q -o BatchMode=yes "$NODE:/tmp/${safe}.tar" "$OUT/images/${safe}.tar" 2>/dev/null; then
        echo "  образ выгружен: ${safe}.tar ($(du -h "$OUT/images/${safe}.tar" | cut -f1), тег $tag)"
        break
      fi
    fi
  done
  "${SSH[@]}" "sudo rm -f /tmp/${safe}.tar" >/dev/null 2>&1 || true
done

echo "[export] 6) конфиги узла"
"${SSH[@]}" 'sudo cp /opt/kata/share/defaults/kata-containers/configuration.toml /tmp/kata-configuration.toml; sudo cp /var/snap/microk8s/current/args/containerd-template.toml /tmp/containerd-template.toml; sudo chmod 644 /tmp/kata-configuration.toml /tmp/containerd-template.toml' >/dev/null 2>&1 || true
for f in /tmp/kata-configuration.toml /tmp/containerd-template.toml /tmp/mlscan-sandbox-digest; do
  scp -q -o BatchMode=yes "$NODE:$f" "$OUT/node/" 2>/dev/null || true
done
"${SSH[@]}" 'sudo microk8s status' > "$OUT/cluster/microk8s-status.txt" 2>/dev/null || true

echo "[export] 7) кластерные объекты"
kubectl --context "$CTX" get clusterpolicy -o yaml > "$OUT/cluster/kyverno-clusterpolicies.yaml" 2>/dev/null || true
kubectl --context "$CTX" -n kyverno get deploy,cm -o yaml > "$OUT/cluster/kyverno-install.yaml" 2>/dev/null || true
kubectl --context "$CTX" get sc,runtimeclass -o yaml > "$OUT/cluster/sc-runtimeclass.yaml" 2>/dev/null || true
kubectl --context "$CTX" get ns -o yaml > "$OUT/cluster/namespaces.yaml" 2>/dev/null || true
kubectl --context "$CTX" get crd -o name > "$OUT/cluster/crds.txt" 2>/dev/null || true

echo "[export] 8) git-состояние"
git rev-parse HEAD > "$OUT/repo/head.txt" 2>/dev/null || true
git remote -v > "$OUT/repo/remotes.txt" 2>/dev/null || true
git status --short > "$OUT/repo/status.txt" 2>/dev/null || true
git log --oneline -20 > "$OUT/repo/log.txt" 2>/dev/null || true

echo "[export] готово: $OUT"
du -sh "$OUT" 2>/dev/null | awk '{print "  размер:", $1}'
