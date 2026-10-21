[Русский](../08-testing-guide.md) | **English**

# 08. MLScan testing guide (what to test and where to connect)

A practical guide to verifying the deployed system. Demo data and expected results are below. The
architecture description is in `./07-implemented-architecture.md`.

---

## 1. Where to connect

| What | Where |
|-----|-----|
| Cluster | `<CLUSTER>` = **<NODE_IP>** (MicroK8s) |
| kubectl | context `microk8s` |
| SSH to the node | `ssh <user>@<CLUSTER>` |
| **Ingress gateway** | `http://<NODE_IP>:30217` (HTTP `istio-ingressgateway`) |
| Analytics (UI+API) | host `analytics.mlscan.local` |
| Integrations | host `integrations.mlscan.local` |
| Ops | host `ops.mlscan.local` |
| Testing API | host `api.mlscan.local` |

Namespaces: `mlscan-sandbox`, `mlscan-monitoring`, `mlscan-testing`, `mlscan-analytics`,
`mlscan-integrations`, `mlscan-ops`, `mlscan-ingress`.

> **Access is via Ingress (Istio)**; per-service NodePorts are disabled (see `deploy/ingress/`).
> Option 1 (without DNS changes) — gateway + Host header:
> ```bash
> GW=<NODE_IP>:30217
> curl -sS --noproxy '*' -H 'Host: analytics.mlscan.local' http://$GW/healthz
> ```
> Option 2 — add hosts entries (or DNS) and access by name:
> ```
> <NODE_IP> analytics.mlscan.local integrations.mlscan.local ops.mlscan.local api.mlscan.local
> ```
> ```bash
> curl -sS --noproxy '*' http://analytics.mlscan.local:30217/healthz
> ```
> In the examples below the address `<NODE_IP>:308xx` corresponds to the MLScan host: run via
> `$GW` with the required `Host:` (analytics / integrations / ops / api).

> ⚠️ An HTTP proxy is set on the workstation (`http_proxy=http://localhost:1515`) — use
> `curl --noproxy '*'`.

Alternative — port-forward (directly to ClusterIP services):
```bash
kubectl -n mlscan-analytics  port-forward svc/mlscan-analytics  18080:8080
kubectl -n mlscan-integrations port-forward svc/mlscan-integrations 18081:8080
kubectl -n mlscan-ops        port-forward svc/mlscan-ops        18082:8080
kubectl -n mlscan-testing    port-forward svc/mlscan-testing    18083:8080
```

Checking stack liveness (via the gateway):
```bash
curl -sS --noproxy '*' -H 'Host: ops.mlscan.local' http://<NODE_IP>:30217/health/stack
```

---

## 2. Demo data and expected results

`poc/scan/*.pkl` — deliberately malicious/clean samples (sandbox only):

| File | Attack class | Expected verdict |
|------|-------------|-------------------|
| `evil0.pkl`, `evil1.pkl`, `evil4.pkl` | RCE `os.system` | **Malicious** |
| `evil2.pkl`, `evil5.pkl` | `exec` in memory + modification of `builtins` | **Malicious** |
| `evil3.pkl` | network access on load (`urlopen`) | **Malicious** |
| `evil6.pkl` | reading honeypot credentials + leak to the sinkhole | **Malicious** |
| `benign.pkl` | harmless dictionary | **Safe** |
| `toy.pkl` | model with `predict` (non-standard module) | **Safe** (note A-19 low) |

---

## 3. What can be tested

### Stage 1 — Sandbox (isolation)
```bash
# Run a sample in the Kata microVM through the harness
bash deploy/stage1/run-sandbox.sh evil2.pkl pickle     # -> behavior_findings: F-32, F-20
bash deploy/stage1/run-sandbox.sh evil6.pkl pickle     # -> deception + sinkhole

# Sinkhole hits (the only allowed egress)
kubectl -n mlscan-sandbox logs deploy/sinkhole | tail

# Escape/red-team test: 7 isolation checks (all must be PASS)
kubectl -n mlscan-sandbox delete job mlscan-redteam --ignore-not-found
kubectl apply -f deploy/stage5/40-redteam-job.yaml
kubectl -n mlscan-sandbox logs -f job/mlscan-redteam

# eBPF (Falco): sandbox events
kubectl -n mlscan-monitoring logs ds/falco -c falco | grep "MLScan sandbox"
```

### Stage 2 — Testing service
```bash
bash deploy/stage2/run-scan.sh poc/scan/evil2.pkl pickle
#  -> state=done verdict=Malicious [L1] A-01 + [L3] F-32, F-20
bash deploy/stage2/run-scan.sh poc/scan/benign.pkl pickle   # -> Safe
```

### Stage 3 — Analytics + UI

Access is via the Ingress gateway (see §1). Helper:
```bash
GW=<NODE_IP>:30217
gw(){ curl -sS --noproxy '*' -H "Host: $1" "http://$GW$2"; }   # gw <host> <path>
```
- UI: open **http://analytics.mlscan.local:30217** (with a hosts entry) or `gw analytics.mlscan.local /`.
- API:
```bash
gw analytics.mlscan.local /api/scans | python3 -m json.tool | head
gw analytics.mlscan.local /api/evidence/verify
SID=$(gw analytics.mlscan.local /api/scans | python3 -c 'import sys,json;print(json.load(sys.stdin)["scans"][0]["scan_id"])')
gw analytics.mlscan.local "/reports/$SID.md"
gw analytics.mlscan.local "/reports/$SID.sarif" | python3 -m json.tool | head
```

### Uploading a model via the UI (including large files)

1. Open **http://analytics.mlscan.local:30217** (or `gw analytics.mlscan.local /`).
2. On the **login** page enter the **login/password** (created by `bash deploy/v2/auth/users.sh`;
   alternatively — sign in with an API key). The session is a cookie `mlscan_session` with the
   domain `.mlscan.local` (single sign-on for analytics/ops/integrations).
3. The **"Upload model"** form → choose a file → **"Upload and check"** (format by extension).
3. Upload progress (browser) and check progress (the "Progress" column, auto-refresh every 3 s).
4. Result: a row with the **SHA-256**, size, verdict and policy action; clicking the name opens the
   artifact card.

API (the Analytics UI proxy and the direct testing API):
```bash
# via Analytics (Host: analytics.mlscan.local)
ID=$(curl -sS --noproxy '*' -H 'Host: analytics.mlscan.local' -X POST --data-binary @model.pkl \
     "http://$GW/upload?name=model.pkl&fmt=pickle" | python3 -c 'import sys,json;print(json.load(sys.stdin)["scan_id"])')
gw analytics.mlscan.local "/api/progress/$ID"      # state/stage/progress
gw analytics.mlscan.local /api/overview | python3 -m json.tool | head
gw analytics.mlscan.local /api/stats               # verdicts, volume, hash count

# direct testing API (Host: api.mlscan.local)
curl -sS --noproxy '*' -H 'Host: api.mlscan.local' -X POST --data-binary @big.pkl \
     "http://$GW/scans/upload?name=big.pkl&fmt=pickle"
gw api.mlscan.local /stats
```

> Verified: a ~50 MB file uploads in ~1.2 s and is checked in Kata; progress is visible
> (`queued→static→running→done`), the verdict is set, sha256/size/timings are stored.

### Stage 4 — Integrations / CI/CD Gate / SIEM
```bash
gw integrations.mlscan.local /registry | python3 -m json.tool | head

# Gate on a known-bad hash (evil0) -> block (HTTP 403)
gw integrations.mlscan.local "/gate?sha256=de4e240c47bb26dc9eb77e0cae169c4798845fe4aa8929c710bc7e92bcbb88bd"

# CI helper: scans an artifact and returns an exit code (0 allow / 1 block / 2 review)
#   arguments: <file> <fmt> <gate-url> <host>
bash deploy/stage4/mlscan-gate.sh poc/scan/evil6.pkl pickle http://<NODE_IP>:30217 integrations.mlscan.local; echo "exit=$?"
bash deploy/stage4/mlscan-gate.sh poc/scan/benign.pkl pickle http://<NODE_IP>:30217 integrations.mlscan.local; echo "exit=$?"

# SIEM export
gw integrations.mlscan.local /export/cef | tail
```

### Stage 5 — Operations / metrics
```bash
gw ops.mlscan.local /metrics | grep '^mlscan_' | head -20
gw ops.mlscan.local /quality | python3 -m json.tool | head     # TPR/FPR on the golden set
curl -sS --noproxy '*' -H 'Host: ops.mlscan.local' -X POST "http://$GW/retest"
kubectl -n mlscan-ops get cronjob mlscan-retest                # continuous retest */30
```

### End-to-end scenario
```bash
bash deploy/stage4/mlscan-gate.sh poc/scan/evil0.pkl pickle http://<NODE_IP>:30217 integrations.mlscan.local
#  chain: gate -> testing (L1+L2/L3 in Kata) -> registry -> decision -> exit code
```

---

## 4. Expected results (verified)

- `evil0/1/2/3/4/5/6` → **Malicious**; `benign/toy` → **Safe**.
- Gate on `evil0` (`sha256=de4e240c…`) → **HTTP 403 block**; on `benign` → **200 allow**.
- CI helper: `evil6` → **exit 1**, `benign` → **exit 0**.
- Red-team (Kata): all 7 checks **PASS**; the guest kernel 6.18.35 ≠ the host one 7.0.0-38.
- Quality (golden): **TPR=1.0, FPR=0.0, precision=1.0, accuracy=1.0**.
- Evidence chain: `{"ok": true, "entries": N}`.
- Falco: events `MLScan sandbox harness exec/egress/write`.

---

## 5. Limitations of the test loop

- GPU tests are unavailable (`nvidia.com/gpu=0` on the node).
- UI/API without authentication (test loop); access via the Ingress gateway (HTTP, without TLS).
- Horizontal scaling of services with RWO-PVC is not tested (single-node).

### Why "Dangerous — manual confirmation required" sometimes occurs

Dynamic analysis is always performed, but the verdict `Dangerous` (instead of `Malicious`) means
that the dynamic stage **did not record hard signals** (processes/network/exec). Frequent causes:
- **Python 2**-style pickle (`__builtin__`) — now supported (see the harness fix);
- the model requires **torch/numpy** — now the sandbox image `mlscan-sandbox` contains torch CPU
  (see `deploy/sandbox-image/`), and such models are loaded/executed in dynamic analysis.
Details of the dynamic stage (status, load errors, signals) are now visible in the **artifact card**
(the "Dynamic stage" section).
