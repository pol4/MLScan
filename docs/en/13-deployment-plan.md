# 13. Staged deployment plan

[Русский](../13-deployment-plan.md) | **English**

This document describes the **deployment levels** of MLScan: from a single Python script with Docker
up to a production-grade loop. Every level is **self-sufficient** (fully usable within its analysis
capabilities) and **clearly argued**; the next level only adds capabilities and components.

Practice: [`../../deploy/README.md`](../../deploy/README.md) (choose a level, install, verify),
[`../../deploy/upgrade.md`](../../deploy/upgrade.md) (upgrade N -> N+1).

---

## 1. Principles

1. **Self-sufficiency.** At every level the system can be used as is: it produces a correct result
   within its analysis capabilities. Incompleteness is never concealed: when a verification module
   could not run (the model failed to load, a library is missing, a timeout), the verdict is
   `Inconclusive` with a partial result (coverage accounting works at every level).
2. **Monotonic complexity.** Components are added gradually: a local tool -> an isolated microVM on a
   single node -> services, object storage and a database -> UI and audit -> integrations -> operations.
3. **Upward compatibility.** Moving to the next level does not break the previous one: the API, the
   data and the findings format stay the same; installation is idempotent; evidence is append-only.
4. **One analysis, different infrastructure.** The set of supported formats does not depend on the
   level: format adapters are the shared module [`../../poc/formats.py`](../../poc/formats.py), used by
   both the PoC and the testing service.
5. **Explicit boundaries.** Each level states what it does **not** provide, so that a simple level is
   not expected to behave like a production loop.

---

## 2. Levels

### Level 0 - PoC (Python + Docker)

**Argument.** Most risks (RCE on deserialisation, dangerous globals, external references, prompt
injection, secret leaks, structural anomalies) are found by **static analysis without execution**.
So the first level - one script plus Docker - already delivers value and covers the majority of
formats; no infrastructure is needed.

* **Analysis:** static L1 for every format (pickle/torch/numpy, SafeTensors, ONNX, HDF5/Keras, GGUF,
  archives and nested archives, notebooks, scripts, Dockerfiles, HTML/SVG, Jinja templates,
  configs/cards/tokenizers, MCP manifests, datasets, compressed payloads); dynamic L2 in Docker
  (`--network none`, read-only FS, limits) and behaviour L3 for executable formats; Markdown/JSON
  report; coverage-aware verdict.
* **Requirements:** Python 3.10+ (stdlib only) and Docker (for the dynamic stage).
* **Does not provide:** strong isolation (Docker only), history, an API, a UI or audit.
* **Acceptance:** `bash deploy/verify.sh 0` - static analysis finds `A-01` in a malicious pickle and
  `INJ-01` in a GGUF chat_template; with `--static-only` the verdict is `Inconclusive`.
* **Directories:** [`../../poc/`](../../poc).

### Level 1 - Isolated sandbox (microVM) on a single node

**Argument.** Dynamic analysis means **executing untrusted code**, and even "inert" formats are loaded
by native engines that can themselves be vulnerable. A barrier stronger than a container is needed:
a separate kernel (Kata microVM), network denial, honeypots, observability.

* **Analysis:** the same, but L2/L3 run in a microVM with the full set of restrictions; the artefact is
  served to the sandbox by a service (never mounted) and the environment is destroyed after the scan.
* **Requirements:** single-node Kubernetes, RuntimeClass `kata` (or `gvisor`), an image registry, the
  `mlscan-sandbox` image.
* **Does not provide:** an HTTP API, artefact or history storage, a UI.
* **Acceptance:** `bash deploy/verify.sh 1` - the `mlscan-sandbox` namespace, RuntimeClass `kata` and
  a NetworkPolicy exist; the red-team Job confirms isolation.
* **Directories:** [`../../deploy/stage1/`](../../deploy/stage1), [`../../deploy/sandbox-image/`](../../deploy/sandbox-image).

### Level 2 - Testing service (S3 + PostgreSQL)

**Argument.** Models can be huge (hundreds of GB) and are submitted repeatedly from CI/platforms.
Hence: object storage addressed by content (`sha256/<name>`, deduplication), metadata in a database,
streaming intake and sandbox orchestration as a service.

* **Analysis:** everything from level 1, plus HTTP intake, verdict and findings over the API, history
  by `sha256`, RU/EN service messages, honest coverage in the verdict.
* **Requirements:** level 1 + Garage (S3) + PostgreSQL + an image registry.
* **Does not provide:** scoring/policy/evidence/UI (level 3), registry/gate (4), metrics/quality (5).
* **Acceptance:** `bash deploy/verify.sh 2` - `POST /scans/upload` of a malicious pickle yields
  `Malicious`/`Dangerous`, a benign safetensors yields `Safe`; the object is in S3 and the row is in
  the database.
* **Directories:** [`../../deploy/v2/data/`](../../deploy/v2/data), [`../../deploy/v2/db/`](../../deploy/v2/db),
  [`../../deploy/stage2/`](../../deploy/stage2).

### Level 3 - Analytics, Policy Engine, Evidence and UI

**Argument.** A scan result must become a **decision** and **evidence**: scoring, policy (what to
block or send for review), an immutable journal (hash chain) and an analyst-facing interface with
access control.

* **Capabilities:** scoring and the Policy Engine, append-only evidence (file + PostgreSQL mirror),
  JSON/Markdown/SARIF reports, web UI: sign-in (users/API keys/roles), language switch, `/settings`
  for the global system language, the incomplete-scan banner.
* **Requirements:** levels 1-2 + Ingress (Istio) for external access + the localisation module.
* **Does not provide:** supply-chain integrations (level 4) or the operations loop (level 5).
* **Acceptance:** `bash deploy/verify.sh 3` - analytics sees the scans, evidence verifies, the sign-in
  page is served, sign-in and reports work.
* **Directories:** [`../../deploy/stage3/`](../../deploy/stage3), [`../../deploy/v2/auth/`](../../deploy/v2/auth),
  [`../../deploy/i18n/`](../../deploy/i18n), [`../../deploy/ingress/`](../../deploy/ingress).

### Level 4 - Integrations (registry, CI gate, SIEM, threat intel)

**Argument.** Scanning only matters if it **stops** a dangerous model on its way to production. That
requires a CI gate, a registry of verified artefacts and event export to a SIEM.

* **Capabilities:** model registry by SHA-256, `POST /gate` with an allow/block/review decision and a
  CI exit code, SIEM export (NDJSON/CEF), threat-intel watch lists.
* **Requirements:** levels 2-3.
* **Does not provide:** quality metrics, retest, retention/TTL or backup (level 5).
* **Acceptance:** `bash deploy/verify.sh 4` - `/gate` blocks a known-bad hash and the registry is
  reachable.
* **Directories:** [`../../deploy/stage4/`](../../deploy/stage4).

### Level 5 - Production operations

**Argument.** Long-running operation requires observability (metrics/alerts), quality control
(TPR/FPR on a golden set), continuous re-scanning, storage management (TTL/quarantine) and recovery
(backup with verification).

* **Capabilities:** Prometheus metrics, `/quality` (TPR/FPR), `/sla`, cron `/retest`, the red-team
  Job, `/alerts`, retention/TTL + quarantine + tombstones, backup/restore with verification, PDB,
  attestation.
* **Requirements:** levels 3-4 + lifecycle + backup.
* **Acceptance:** `bash deploy/verify.sh 5` - metrics are served, quality is `TPR=1.0/FPR=0.0`, the
  retest/lifecycle/backup CronJobs exist; `--full` runs the corpus (141 samples).
* **Directories:** [`../../deploy/stage5/`](../../deploy/stage5), [`../../deploy/v2/lifecycle/`](../../deploy/v2/lifecycle),
  [`../../deploy/v2/backup/`](../../deploy/v2/backup).

---

## 3. Summary table

| Lvl | Analysis | New components | Verification | Next step |
|-----|----------|----------------|--------------|-----------|
| 0 | static for every format + dynamic/behaviour in Docker | Python, Docker | `verify.sh 0` | microVM instead of a container |
| 1 | + L2/L3 isolation in a microVM | Kubernetes (1 node), Kata/gVisor, registry, sandbox image | `verify.sh 1` | HTTP intake and storage |
| 2 | + large artefact intake, deduplication, history | Garage S3, PostgreSQL, testing service | `verify.sh 2` | decisions, audit, UI |
| 3 | + scoring, policy, evidence, UI (RU/EN) | authz, i18n, Ingress | `verify.sh 3` | embed into the supply chain |
| 4 | + registry, CI gate, SIEM | integrations service | `verify.sh 4` | operations loop |
| 5 | + metrics, quality, retest, lifecycle, backup | ops, lifecycle, backup | `verify.sh 5` | - |

---

## 4. Cross-cutting capabilities (available at every level)

* **A single format analysis layer** - `poc/formats.py` (the PoC and the service share one adapter set).
* **An honest verdict** - coverage accounting: `Inconclusive` plus the list of what was not checked
  instead of a false `Safe`.
* **RU/EN localisation** - in the PoC (`--lang`), in the services and in the UI; the global language
  setting (`MLSCAN_LANG` at startup plus `POST /settings/language` for an administrator, stored in the
  database).
* **A synthetic corpus** - [`../../tests/vulnerabilities/`](../../tests/vulnerabilities):
  141 samples (87 malicious + 54 benign, including ~198 MB ones) and `REPORT.md`
  (`87/87 detected, 0/54 false positives`).

---

## 5. Out of scope

* Cross-zone storage replication and a DR runbook (in a single-node setup these are external procedures).
* OIDC/Keycloak and mTLS (currently API keys and database users; SSO between services via a cookie on a
  shared domain).
* GPU analysis and running models on GPUs (a separate node pool).
* Detection of dormant payloads that need specific data to activate - partially covered by the
  behavioural stage; full coverage requires a fuzzing loop (the red-team Job is the foundation).
