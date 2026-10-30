#!/usr/bin/env bash
# E2E L1a: импорт образа движка (по digest) + server-side copy OCI-архива в registry/ + allowlist/admission.
#   bash tests/e2e/registry_images_e2e.sh
set -uo pipefail
NS=mlscan-testing
D="sha256:$(python3 -c 'print("a"*64)')"
pod() { kubectl -n "$NS" get pods -l app=mlscan-testing -o json | jq -r '[.items[]|select(.metadata.deletionTimestamp==null and .status.phase=="Running")][0].metadata.name'; }
KEY="$(kubectl -n "$NS" get secret mlscan-keys -o jsonpath='{.data.MLSCAN_KEYS}' | base64 -d \
  | python3 -c 'import json,sys;d=json.load(sys.stdin);print([k for k,v in d.items() if v.get("roles")==["admin"]][0])')"

echo "== включаем allowlist реестра (mlscan-registry) =="
kubectl -n "$NS" set env deploy/mlscan-testing REGISTRY_ALLOWLIST=mlscan-registry >/dev/null
kubectl -n "$NS" rollout status deploy/mlscan-testing --timeout=150s >/dev/null
POD="$(pod)"

kubectl -n "$NS" exec -i "$POD" -- python3 - "$KEY" "$D" <<'PY'
import hashlib, json, os, sys, urllib.request, urllib.error
sys.path.insert(0, "/opt/s3")
from s3client import S3
key, digest = sys.argv[1], sys.argv[2]
op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
s3 = S3(os.environ["S3_ENDPOINT"], os.environ["S3_ACCESS_KEY"], os.environ["S3_SECRET_KEY"],
        region=os.environ.get("S3_REGION", "garage"), bucket=os.environ["S3_BUCKET"], timeout=120)

def api(method, path, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request("http://127.0.0.1:8080" + path, data=data, method=method,
                                 headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"})
    try:
        with op.open(req, timeout=60) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")

# 1) OCI-архив (условный blob) лежит в S3
tar = os.urandom(2 * 1024 * 1024)
s3.put("import-src/vllm-oci.tar", tar)
ref = "mlscan-registry/team/vllm@" + digest

st, rec = api("POST", "/images/import", {"ref": ref, "oci_tar_key": "import-src/vllm-oci.tar",
                                         "size": len(tar), "sbom": "spdx:demo", "source": "ci"})
assert st == 201, (st, rec)
sk = rec["stored_key"]
assert sk == f"registry/images/{digest.split(':')[1]}/blob.tar", sk
assert s3.exists(sk), "OCI blob не скопирован в registry/"
st2, g = api("GET", "/images/" + digest)
assert st2 == 200 and g["ref"] == ref and g["status"] == "registered", (st2, g)

# 2) admission: не по digest -> отказ; чужой реестр -> отказ
st3, e3 = api("POST", "/images/import", {"ref": "mlscan-registry/team/vllm:latest"})
assert st3 == 400, (st3, e3)
st4, e4 = api("POST", "/images/import", {"ref": "docker.io/library/python@" + digest})
assert st4 == 403, (st4, e4)
st5, v = api("GET", "/images/verify?ref=docker.io/library/python@" + digest)
assert st5 == 200 and v["allowed"] is False, (st5, v)
st6, v2 = api("GET", "/images/verify?ref=" + urllib.request.quote(ref))
assert v2["allowed"] is True, v2
print("  [OK]   import по digest + копия в registry/ + admission (digest/allowlist)")
PY

echo "== снимаем allowlist =="
kubectl -n "$NS" set env deploy/mlscan-testing REGISTRY_ALLOWLIST- >/dev/null
kubectl -n "$NS" rollout status deploy/mlscan-testing --timeout=150s >/dev/null
echo "P0..L1a registry: OK"
