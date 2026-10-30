#!/usr/bin/env bash
# E2E U10: CI-gate в сервисе integrations по паре (image digest, model sha) — прокси к v3 /gate.
#   bash tests/e2e/integrations_gate_e2e.sh
set -uo pipefail
TNS=mlscan-testing; INS=mlscan-integrations
TPOD="$(kubectl -n "$TNS" get pods -l app=mlscan-testing -o json | jq -r '[.items[]|select(.metadata.deletionTimestamp==null and .status.phase=="Running")][0].metadata.name')"
IPOD="$(kubectl -n "$INS" get pods -l app=mlscan-integrations -o json | jq -r '[.items[]|select(.metadata.deletionTimestamp==null and .status.phase=="Running")][0].metadata.name')"
KEY="$(kubectl -n "$TNS" get secret mlscan-keys -o jsonpath='{.data.MLSCAN_KEYS}' | base64 -d \
  | python3 -c 'import json,sys;d=json.load(sys.stdin);print([k for k,v in d.items() if v.get("roles")==["admin"]][0])')"
SHA="$(kubectl -n "$TNS" exec -i "$TPOD" -- python3 - "$KEY" <<'PY'
import json, sys, urllib.request
key=sys.argv[1]; op=urllib.request.build_opener(urllib.request.ProxyHandler({}))
sha="d"*64; img="mlscan-registry/team/vllm@sha256:"+"e"*64
def api(m,p,pl=None):
    d=json.dumps(pl).encode() if pl is not None else None
    r=urllib.request.Request("http://127.0.0.1:8080"+p,data=d,method=m,headers={"Authorization":"Bearer "+key,"Content-Type":"application/json"})
    return json.loads(op.open(r,timeout=60).read() or b"{}")
b=api("POST","/bundles",{"model_sha256":sha,"engine_image":img,"engine_manifest":{"entrypoint":"vllm serve"},"prompt_set":"ps-v9"})
api("POST",f"/bundles/{b['bundle_id']}/verdict",{"verdict":"Malicious","safety_fail":1,"pass_rate":0.4})
print(sha)
PY
)"
echo "model=$SHA"
kubectl -n "$INS" exec -i "$IPOD" -- python3 - "$SHA" "$KEY" <<'PY'
import json, sys, urllib.request, urllib.parse as up
sha,key=sys.argv[1],sys.argv[2]; img="mlscan-registry/team/vllm@sha256:"+"e"*64
op=urllib.request.build_opener(urllib.request.ProxyHandler({}))
u="http://127.0.0.1:8080/gate?image="+up.quote(img)+"&model="+sha
d=json.loads(op.open(urllib.request.Request(u,headers={"Authorization":"Bearer "+key}),timeout=30).read())
assert d.get("decision")=="block", d
assert d.get("bundle_id"), d
# N3: прокси передаёт ссылку на подписанное решение (аттестацию) и её источник
assert d.get("attestation_digest"), d
assert d.get("source") in ("bundle-verdict", "artifact-verdict", "policy-default"), d
print("  [OK]   integrations /gate decision=block bundle=", d["bundle_id"][:16],
      "| source=", d.get("source"), "| attestation=", d["attestation_digest"][:20])
PY
RC=$?; [ "$RC" = "0" ] || { echo "[FAIL] integrations gate e2e"; exit 1; }
echo "P0..L4 integrations gate: OK"
