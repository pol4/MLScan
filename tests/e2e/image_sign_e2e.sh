#!/usr/bin/env bash
# E2E B4-lite: подпись и SBOM образов движков; политика IMAGES_REQUIRE_SIGNED.
#   bash tests/e2e/image_sign_e2e.sh
set -uo pipefail
CTX="${MLSCAN_KUBE_CONTEXT:-microk8s}"; NS=mlscan-testing
POD="$(kubectl --context "$CTX" -n "$NS" get pods -l app=mlscan-testing -o json | jq -r '[.items[]|select(.metadata.deletionTimestamp==null)][0].metadata.name')"
KEY="$(kubectl --context "$CTX" -n "$NS" get secret mlscan-keys -o jsonpath='{.data.MLSCAN_KEYS}' | base64 -d | python3 -c 'import json,sys;d=json.load(sys.stdin);print([k for k,v in d.items() if v.get("roles")==["admin"]][0])')"
# политика — включаем на время теста
kubectl --context "$CTX" -n "$NS" set env deploy/mlscan-testing IMAGES_REQUIRE_SIGNED=1 >/dev/null
kubectl --context "$CTX" -n "$NS" rollout status deploy/mlscan-testing --timeout=240s >/dev/null
POD="$(kubectl --context "$CTX" -n "$NS" get pods -l app=mlscan-testing -o json | jq -r '[.items[]|select(.metadata.deletionTimestamp==null)][0].metadata.name')"
kubectl --context "$CTX" -n "$NS" exec -i "$POD" -- python3 - "$KEY" <<'PY'
import json, sys, urllib.error, urllib.request
key = sys.argv[1]
op = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def api(method, path, payload=None, timeout=60):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request("http://127.0.0.1:8080" + path, data=data, method=method,
                                 headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"})
    try:
        with op.open(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


DIG = "sha256:" + "d" * 64
IMG = "mlscan-registry/team/vllm@" + DIG
MODEL = "e" * 64

# 1) регистрируем образ движка (неподписанный)
st, r = api("POST", "/images/import", {"ref": IMG, "source": "import"})
assert st in (200, 201), (st, r)
st, d = api("GET", "/images/" + DIG)
assert st == 200 and d["signed"] is False and d["sbom_present"] is False, (st, d)
print("  [OK]   образ зарегистрирован: signed=%s sbom=%s" % (d["signed"], d["sbom_present"]))

# 2) при IMAGES_REQUIRE_SIGNED: bundle с неподписанным движком — отказ
st, b = api("POST", "/bundles", {"model_sha256": MODEL, "engine_image": IMG, "prompt_set": ""})
assert st == 400 and "не подписан" in (b.get("error") or ""), (st, b)
print("  [OK]   создание bundle с неподписанным движком отклонено (400)")

# 3) подписываем + SBOM -> bundle создаётся
st, sig = api("POST", "/images/" + DIG + "/sign", {})
assert st == 200 and sig["signature"].startswith("hmac-sha256:"), (st, sig)
st, sb = api("POST", "/images/" + DIG + "/sbom",
             {"sbom": json.dumps({"spdxVersion": "SPDX-2.3", "name": "vllm-image",
                                  "packages": [{"name": "vllm", "versionInfo": "0.6"}]})})
assert st == 200 and sb["sbom_bytes"] > 0, (st, sb)
st, d2 = api("GET", "/images/" + DIG)
assert st == 200 and d2["signed"] and d2["sbom_present"], (st, d2)
print("  [OK]   образ подписан (%s…) и SBOM сохранён" % sig["signature"][:22])

st, b2 = api("POST", "/bundles", {"model_sha256": MODEL, "engine_image": IMG, "prompt_set": ""})
assert st in (200, 201), (st, b2)
print("  [OK]   bundle с подписанным движком создан:", b2["bundle_id"])

# 4) другой неподписанный digest — по-прежнему отказ
DIG2 = "sha256:" + "f" * 64
api("POST", "/images/import", {"ref": "mlscan-registry/team/other@" + DIG2, "source": "import"})
st, b3 = api("POST", "/bundles", {"model_sha256": MODEL, "engine_image": "mlscan-registry/team/other@" + DIG2,
                                  "prompt_set": ""})
assert st == 400, (st, b3)
print("  [OK]   другой неподписанный образ также отклонён")
PY
RC=$?; [ "$RC" = "0" ] || { kubectl --context "$CTX" -n "$NS" set env deploy/mlscan-testing IMAGES_REQUIRE_SIGNED=0 >/dev/null; echo "[FAIL] image sign e2e"; exit 1; }
kubectl --context "$CTX" -n "$NS" set env deploy/mlscan-testing IMAGES_REQUIRE_SIGNED=0 >/dev/null
kubectl --context "$CTX" -n "$NS" rollout status deploy/mlscan-testing --timeout=240s >/dev/null
echo "B4-lite image sign/sbom: OK"
