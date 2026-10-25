# 19. v3 implementation status (as-built, English summary)

Current stand: single-node microk8s (`rtx-cluster`), namespaces `mlscan-*`. Code `deploy/v3/**`,
tests `tests/**`. Full RU status: `../19-implementation-as-built.md`.

## Phases
- **P0–P9**: done on the stand — range-read + shared content-addressed pool + refs; TLS egress S3;
  3×Garage RF=2 prototype; ingest import/quotas/resume/fair-share; persistent priority queue + orchestrator
  + **signed policy fail-closed** + detector version registry; streaming index-driven static
  (safetensors/**GGUF/ONNX**); archive walk (zip CD/tar) with depth budget + zip-slip/bomb; deterministic
  slice selector (dynamic plan recorded in scan); evidence HMAC chain + WORM anchor; per-tenant KMS;
  `/v3/metrics` + `/v3/slo` (+ per-tenant metrics in ops `/metrics`); leader-election; v2→v3 migration.
- **L0–L4**: done on the stand — UI typing/badge/image import; LLM classifier (auto for GGUF);
  image registry by digest + allowlist/admission; single Kata env (hardened Job passes Kyverno) + precheck;
  eBPF events → `LLM-B-01..05` (nonce); XLSX `questions_v9` → DB/versions + rules/judge/tolerances +
  domain→class editor; bundle verdict + signed attestation + CI gate (`/gate?image&model`,
  integrations `/gate?image&model`).
- **H1** done (background HF downloads with resume, browser-independent, mock-HF).
- **H2** done — llama.cpp CPU image `ghcr.io/ggml-org/llama.cpp@sha256:1fa7…` (pull by kubelet; pod egress is
  restricted by our NetworkPolicy, node has internet).
- **H3** partial (CPU, no Kata/eBPF) — 10 random customer questions via llama.cpp: `total=10, passed=5,
  safety_fail=5, pass_rate=0.5`.

## Tests
190 unit (tests/v3 167, s3 22, formats 1), 6 browser (puppeteer), 42 e2e scripts on real
Garage/PostgreSQL/cluster — all green. Run: `python3 -m unittest discover -s tests/v3`;
`bash tests/ui/run_ui_tests.sh`; `bash tests/e2e/<name>.sh`.

## Remaining
B1 separate RuntimeClass `kata-btf` (BTF Kata kernel) + in-guest eBPF → full H3; B2 GPU pool;
B3 real Hugging Face (token + egress allowlist); B4 Harbor+cosign/SBOM; B5 Vault/TSA/WORM + mTLS;
B6 multi-node HA/DR + GitOps; B7 trusted judge model; B8 HDF5 adapter + full scan-flow integration;
B9 1 TB perf. See plan `../15-implementation-plan.md` §8.9/§8.10/§9.
