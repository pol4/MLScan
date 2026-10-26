# 20. Model verification operator guide (MLScan v3, English summary)

Full RU guide: `../20-operator-guide.md`. This is the English core for operators/analysts who
**upload models and interpret results**.

## 0. Access

| Item | Value |
|------|-------|
| UI | `http://analytics.mlscan.local:30217` (HTTPS `https://analytics.mlscan.local:30921`) |
| API (testing service) | `http://api.mlscan.local:30217` (or your NodePort/port-forward) |
| Logins / API keys | issued by the administrator (`admin`, `analyst`; keys `admin`/`ci-reader`/`service`) |
| Engine images | registry `mlscan-registry`; **launch by digest only** |

## 1. Data transfer requirements
- **Non-LLM model / dataset / script / archive** — UI “Downloads → Models (non-LLM)” or `POST /scans/upload`.
- **Local LLM** — “Local LLMs”: file + **required engine** from already downloaded engines.
- **LLM from Hugging Face** — “Model from HF”: search with filters; **HF token** (stored masked); **engine required**.
- **Engine image** — “Inference engines”: import by `…@sha256:…` or OCI archive in S3.
- **Large files (TB class)** — direct-to-S3: `/uploads/initiate` → parts → `/scans/complete`
  (resumable, dedup by `sha256`).
- Key limits: upload ≤ **1 TiB**; static reads first **64 MiB** prefix (index formats read full index);
  archive members **32 MiB/member, 128 MiB/archive**; 30 uploads/min; 5 in-flight scans;
  dynamic only within sandbox limits (~6 GiB) — TB models are static+sampled.
- Do not put secrets in file names/metadata; the HF token is entered in a dedicated form and shown
  only masked (`hf_***`).

## 2. Scenarios
- **S1 non-LLM model**: upload → wait `queued→running→done` → read verdict, severity/risk, findings, coverage.
- **S2 LLM**: ensure the engine is downloaded → save HF token if needed → search/filters → pick model →
  **select engine** → download → bundle created → inference + prompt set → read verdict/behavior/answers/coverage.
- **S3 archive (all formats)**: upload `fmt=zip|tar` → member walk (incl. nested) → aggregate verdict + member list.
- **S4 engine mismatch**: “Engine rebind” (model sha256 + another downloaded engine) → **new bundle**, no re-upload.
- **S5 CI gate**: `GET /gate?image=<…@sha256:…>&model=<sha256>` → `allow|block|quarantine` + attestation.
- **S6 after rule updates**: `POST /retest`; quality via `GET /quality` (TPR/FPR).

## 3. Interpreting results
- **Verdicts**: `Safe` (full coverage, nothing significant), `Needs review` (medium findings),
  `Dangerous` (high/critical without hard dynamics, or hard dynamic signals),
  `Malicious` (high/critical **and** dangerous behavior), `Inconclusive` (coverage incomplete and
  nothing proves danger — **not “safe”**).
- **Severity/score**: `critical>high>medium>low>info`; `risk_score = min(10, top + 0.2·rest)`,
  `max_severity`. Finding groups: `A-*`, `F-*`, `EXEC-*`, `INJ-*`, `SEC-*`, `FMT-*`, `BD-*`, `IMG-*`, `LLM-B-*`.
  Hard dynamic signals: network attempts, process/command launch, in-memory exec, native library
  load, file writes, timeout.
- **Coverage → Inconclusive**: modules are `static`, `dynamic`, `behavior`; a module counts as done only
  if it ran without errors. If anything failed, the system will not say `Safe` but `Inconclusive` with
  the list of unchecked items (unless partial data already proves danger).
- **Policy**: `action ∈ {allow, quarantine, block}` (default `quarantine`); configured by the admin (`/policy`).
- **Evidence/attestation**: append-only HMAC journal (`GET /api/evidence/verify`), signed attestation for
  the (image, model) pair, decision via `/gate`, reproducible for the same bundle.
- **LLM behavior** (`LLM-B-*`): shell/interpreter (01), external egress (02; local/sinkhole allowed),
  honeypot secret reads (03), executable memory (04), module load (05).

## 4. Limits affecting conclusions
Sampling for large models/archives (coverage is explicit); design limits (`14-limitations.md`);
verdicts are bound to a bundle (image+model+rule versions) — a rule update produces a **new** bundle.

## 5. Appendix
- API cheat sheet and error codes: see RU guide §5.1–5.2.
- Operator checklist: artifact type/format clear; upload completed (`sha256`/`size` match); coverage full or
  reason understood; verdict/action read; CI gate checked; decision recorded.
- Protocol template: see RU guide §5.4.
