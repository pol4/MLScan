# 20. MLScan operator guide (system usage)

Practical, verified flow for the deployed system. Every step below is exercised by the browser E2E
`tests/ui/full_browser_e2e.js` (16 steps, real models: local GGUF 278 MB, Hugging Face model 291.5 MB,
safetensors, archive).

## 0. Access

| Item | Value |
|---|---|
| UI (HTTP/HTTPS) | `http://analytics.mlscan.local:30217` / `https://analytics.mlscan.local:30921` (self-signed) |
| Logins | `admin / Admin-MLScan-1`, `analyst / Analyst-MLScan-1` |
| Testing API | `http://mlscan-testing.mlscan-testing.svc.cluster.local:8080` (in-cluster) |
| API keys | Secret `mlscan-keys` (roles `admin` / `ci` / `svc`) |

## 1. What can be checked

- **Non-LLM models** (safetensors, ONNX, HDF5, Keras, pickle, GGUF-as-artifact) — “Downloads → Models”.
- **Archives** (zip/tar) — traversed with a depth limit, verdict is the worst element.
- **Local LLM (GGUF)** — “Downloads → Local LLMs” (an engine is **required**): upload → scan → bundle.
- **Hugging Face LLM** — “Downloads → Model from HF”: real search, real download, bundle.
- **Engine images** — “Downloads → Engines”: register by digest, sign, attach SBOM.

## 2. Quick start

1. Sign in.
2. Scroll to **Downloads**, pick the tab for your data.
3. Upload the file (for LLMs select an **engine**; for HF enter a query, optionally an HF token).
4. Wait for completion (status line / new artifact row).
5. Open the artifact card (verdict, coverage, findings). For LLMs run **“Bundle test”** to perform
   inference and get the bundle verdict.

## 3. Downloads tabs

| Tab | Purpose | Key elements |
|---|---|---|
| **Models** | plain files and archives | file picker, type, Upload |
| **Local LLMs** | GGUF upload + bundle | file picker, engine list, Upload, status (`bundle b-…`) |
| **Engines** | engine images, sign, SBOM | `ref@sha256:…`, Import, Sign, list with `[signed]/[unsigned]/[sbom]` |
| **Model from HF** | HF search + download | query, type, quantization, engine, Search, per-repo download buttons, status (progress, sha, bundle) |
| **Bundle test** | inference over the prompt set | model `sha256` or `bundle_id`, Run test, status `test started: job …, questions N, GPU/CPU` → `test finished: verdict …, decision …, attestation …` |

HF token: stored encrypted per tenant, masked (`saved hf_***1234`); saving an empty value clears it.

## 4. Scenarios

- **S1 non-LLM**: Models → upload → open card → verdict/coverage/findings.
  *Verified: real safetensors → `Inconclusive`; real zip (safetensors + pickle + nested zip) → `Dangerous`.*
- **S2 local LLM + inference**: Local LLMs → engine + GGUF → Upload (bundle created) → Bundle test by
  `sha256` → verdict + attestation.
  *Verified: `gemma-3-270m-it-Q8_0.gguf` (278 MB) → `Needs review`, `block`, attestation `sha256:9a416ec2…`.*
- **S3 HF model + inference**: save token (private repos) → Model from HF → query/type/quant/engine →
  Search → download → Bundle test.
  *Verified: 14 results; `unsloth/gemma-3-270m-it-GGUF` (Q8_0) downloaded in **40 s (291.5 MB)** →
  `Needs review`, `block`, attestation `sha256:35505d7c…`; in-guest eBPF findings `LLM-B-01/03/04`.*
- **S4 archive**: as S1 with zip/tar.
- **S5 engine rebind**: rebind panel — model sha + another engine → new bundle → Bundle test again.
- **S6 CI gate**:
  `GET /gate?image=<ref@sha256:…>&model=<model sha256>` → `{decision, source, verdict, attestation_digest, signature}`.
  `block` on critical failures, `quarantine` when there is no verdict (fail-closed), `allow` only on a
  positive verdict.
- **S7 retest** after updating the prompt set (XLSX): run Bundle test again — a new verdict/attestation
  and a new link in the verdict chain.

## 5. Verdicts

Artifact: `Safe` (no findings, full coverage), `Inconclusive` (incomplete coverage — manual decision),
`Dangerous`/`Malicious` (dangerous behaviour found), `Needs review`.
Bundle (after inference): `Safe` (all cases passed), `Needs review` (critical failures, `safety_fail > 0`),
`Inconclusive`. Every bundle verdict is signed and appended to the immutable chain (see §7).

## 6. Engines

Import by `ref@sha256:…`; sign platform-side (interim to cosign) — the list shows `[signed]`; with
`IMAGES_REQUIRE_SIGNED=1` bundle creation/rebind/HF download require a signed engine (400 otherwise);
SBOM is stored via `POST /images/<digest>/sbom`.

## 7. Audit, observability, integrity

| What | How |
|---|---|
| Gate decisions (append-only) | `GET /gate/decisions?model=<sha>&limit=N` |
| HF egress journal (append-only) | `GET /hf/egress?limit=N` |
| Verdict chain integrity | `GET /v3/evidence/verify` → `{"ok":true,"count":N,"head":"…"}` |
| Metrics / SLO | `GET /v3/metrics`, `GET /v3/slo` (includes `sensor_coverage`) |

## 8. Quotas, limits, CI tokens

- HF daily quota per tenant: `GET/POST /hf/quota` (admin; `daily_bytes: null` clears it).
- Rate limit: 429 + `Retry-After`; tune with `GET/POST /rate-limit` (admin; `rps=0` disables).
- CI token: `POST /auth/token` (admin) → short-lived HS256 JWT (`subject`, `roles`, `ttl`), then
  `Authorization: Bearer <token>`.

## 9. Verified end-to-end run (reproducible)

```bash
bash tests/e2e/make_fixtures.sh                      # real safetensors/archive/GGUF
kubectl -n mlscan-testing port-forward svc/mlscan-testing 18080:8080 &   # for API checks only
MLSCAN_API_KEY=<admin key> MLSCAN_TESTING_URL=http://localhost:18080 node tests/ui/full_browser_e2e.js
```

Expected: `OK: полный браузерный прогон (несколько примеров, включая LLM и HF) — 16 шагов`
(local LLM inference `Needs review`/`block` + attestation; HF download 291.5 MB/40 s + inference +
`sensor findings LLM-B-01/03/04`; safetensors `Inconclusive`; zip `Dangerous`; gate decision + chain `ok`).

## 10. Troubleshooting

| Symptom | Cause / action |
|---|---|
| `ERR: choose an engine` | no engine registered by digest — import one under Engines |
| `model not found in storage` | model not uploaded: upload a file (S1/S2) or download from HF (S3) |
| `Inconclusive` verdict | incomplete coverage — normal for some formats; check the card |
| Long “Bundle test” | waiting for a GPU slot; for small models use a CPU engine (`gpu=false`) |
| `429` | rate limit — wait `Retry-After` or tune `POST /rate-limit` |
| `401` on API | wrong/expired key or JWT; in-cluster `/llm/*` uses a one-shot run token |
| HF search/download fails | check HF egress policy (`mlscan-hf-egress`) and quota; HF addresses rotate — regenerate with `deploy/ingress/gen-hf-egress.sh` |

## 11. LLM inference report

Bundle verdict + attestation; behavioural findings from in-guest eBPF: `LLM-B-01` shell/interpreter,
`LLM-B-02` external egress (public addresses only), `LLM-B-03` honeypot secret reads, `LLM-B-04`
executable memory (RWX/JIT), `LLM-B-05` kernel module load (`critical`); sensor visibility via
`sensor_events` / `/v3/slo.sensor_coverage`.
