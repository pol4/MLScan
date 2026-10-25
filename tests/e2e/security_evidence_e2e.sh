#!/usr/bin/env bash
# E2E P6: evidence HMAC-цепочка + WORM-анкор + per-tenant KMS + fail-closed.
#   bash tests/e2e/security_evidence_e2e.sh
set -uo pipefail
NS=mlscan-testing
POD="$(kubectl -n "$NS" get pods -l app=mlscan-testing -o json | jq -r '[.items[]|select(.metadata.deletionTimestamp==null)][0].metadata.name')"
kubectl -n "$NS" exec -i "$POD" -- python3 - <<'PY'
import os, sys
sys.path.insert(0, "/opt/v3security")
import evidence, kms
KEY = os.environ.get("MLSCAN_EVIDENCE_KEY", "mlscan-dev-evidence")

chain = []
for i in range(6):
    evidence.append(chain, {"scan_id": f"s{i}", "verdict": "Safe", "n": i}, KEY)
ok, why = evidence.verify_chain(chain, KEY)
assert ok, why
print("  [OK]   evidence: цепочка из 6 звеньев проверена")

# подмена payload -> детект
bad = [dict(e) for e in chain]; bad[2]["payload"] = {"tampered": True}
assert not evidence.verify_chain(bad, KEY)[0]
print("  [OK]   evidence: подмена payload обнаружена (fail-closed)")

# WORM-анкор головы + инвалидация после добавления
a = evidence.anchor_head(chain, KEY, notary="tsa.example")
assert evidence.verify_anchor(chain, a, KEY)
evidence.append(chain, {"n": 6}, KEY)
assert not evidence.verify_anchor(chain, a, KEY)
print("  [OK]   evidence: анкор головы valid, затем инвалидируется после новой записи")

# per-tenant KMS
master = os.environ.get("MLSCAN_EVIDENCE_KEY", "master").encode()
pt = b"model tenant payload"
blob = kms.encrypt(master, "ci-team", pt)
assert kms.decrypt(master, blob) == pt
b2 = dict(blob); b2["tenant"] = "other-team"
assert not kms.verify(b2, master)
print("  [OK]   KMS: roundtrip tenant, cross-tenant доступ отклонён (fail-closed)")
PY
RC=$?; [ "$RC" = "0" ] || { echo "[FAIL] security e2e"; exit 1; }
echo "P0..P6 security/evidence: OK"
