[Русский](../07-implemented-architecture.md) | **English**

# 07. Implemented MLScan architecture (as-built)

Final description of the MLScan system **actually deployed** in the cluster `<CLUSTER>` (MicroK8s
v1.33, containerd, Calico, RuntimeClass `kata`): component composition, network interaction diagram,
data flows, trust boundaries and limitations.

The description covers both the base system for pickle (Stages 0–5) and **v2**: object storage,
PostgreSQL, authentication/authorization with audit and RU/EN localisation.

Source: `deploy/stage1…stage5/`, `deploy/v2/`, `deploy/sandbox-image/`, `deploy/i18n/`,
`deploy/ingress/`. Concept — `../../Concept.md`, design architecture — `./05-architecture.md`,
plan — `./06-implementation-plan.md`, test guide — `./08-testing-guide.md`, target architecture
v2 — `./11-target-architecture-v2.md`, localisation — `./12-i18n.md`.

---

## 1. Overview

MLScan is a system for automatic danger analysis of ML/AI artifacts (the core is pickle, then
format adapters). It is implemented as a set of microservices in **nine namespaces**:
`mlscan-sandbox`, `mlscan-monitoring`, `mlscan-testing`, `mlscan-analytics`,
`mlscan-integrations`, `mlscan-ops`, `mlscan-data` (v2: object storage, PostgreSQL,
ingest, retention/backup), `mlscan-build` (building the sandbox image) and `mlscan-ingress`
(Istio Gateway/VirtualServices and egress policies). All services use the Python standard library
(no external dependencies), the image `python:3.12-slim` (Python 3.12.14); the sandbox
uses a separate image `mlscan-sandbox` (torch CPU and format libraries).

Key as-built principles:
- the artifact is **never executed** in the trusted zone — only in a Kata microVM with network
  egress denied;
- services exchange over HTTP inside the cluster; external access is through the single entry point
  Istio Ingress Gateway (host-based routing);
- **two storage layers**: object storage **S3 (Garage)** for artifacts (key
  `sha256/<name>`, deduplication) and **PostgreSQL** for metadata, findings, evidence,
  users/keys, audit and system settings; file PVCs are retained as local
  hash-chain evidence and as a fallback;
- the Evidence Store is append-only with a hash chain (file on a PVC **and** a mirror in PostgreSQL);
- the UI and service messages are localised **RU/EN**; the language is set globally (`MLSCAN_LANG` at
  startup or a setting in the DB) — see `./12-i18n.md`.

### 1.1 Products and versions used

| Product | Version | Role in MLScan |
|---------|--------|---------------|
| Kubernetes (MicroK8s) | 1.33 | cluster platform |
| `kubectl` | — | management (apply, exec, port-forward) |
| containerd | — | node container runtime |
| Kata Containers | — | sandbox microVM (RuntimeClass `kata`) |
| Node OS | Ubuntu LTS | operating system |
| Kata microVM | its own kernel per pod | sandbox isolation |
| Calico | — | CNI + NetworkPolicy |
| CoreDNS | — | cluster DNS |
| metrics-server | — | resource metrics (HPA readiness) |
| hostpath-provisioner | — | StorageClass (local volume) |
| Falco | driver `modern_ebpf` | eBPF runtime monitoring |
| Python | **3.12.14** (image `python:3.12-slim`) | runtime of all services and the in-sandbox harness — **standard library only** |
| PyTorch (CPU) | **2.14.1+cpu** (sandbox image `mlscan-sandbox:v2`, `deploy/sandbox-image/`) + numpy 2.5.4, safetensors 0.8.0, onnxruntime 1.31.0, h5py 3.16.0, gguf, joblib, dill, cloudpickle | dynamic loading and execution of pickle/torch/numpy/model-as-code models in the sandbox |
| Garage | **v1.0.1** (`dxflrs/garage:v1.0.1`) | S3-compatible object storage of artifacts (`sha256/<name>`, deduplication) |
| PostgreSQL | **16** (`postgres:16-alpine`) | metadata, findings, evidence (hash-chain), users, API keys, `audit_log`, settings (`settings`) |
| Kaniko | executor v1.23.2 | building the sandbox image in the in-cluster registry |
| `pickletools` / `zipfile` / `sys.addaudithook` | Python 3.12 stdlib | static parsing (L1) and observability (L2/L3) |
| Helm | — | Falco installation |
| Image registry (OCI) | — | private registry; **stores the sandbox image** `mlscan-sandbox:v2` |
| Localisation module `deploy/i18n/i18n.py` | — | RU/EN catalog and rules for localising messages/findings (ConfigMap `mlscan-i18n` → `/opt/i18n`) |
| Istio | — | **used for Ingress** (Gateway + VirtualServices); sidecar injection (mTLS/mesh) not enabled; there is an egress gateway |

All MLScan services are our own Python stdlib code on top of the `python:3.12-slim` image;
there are no external service dependencies (DB, queue, brokers) — state is in files on PVCs.

---

## 2. Component composition

### 2.1 `mlscan-sandbox` — isolation and execution (Component 1)

| Object | Type | Purpose |
|--------|-----|-----------|
| `sinkhole` (Deployment + ClusterIP Service) | :8080 HTTP, :4444/9001/1337 TCP | in-cluster "trap": the only allowed egress; logs the requests |
| sandbox Job (on demand) | `runtimeClassName: kata` (Kata 3.32.0), image `mlscan-sandbox:v2` | run the harness from the PoC over the artifact (pickle/torch/numpy/model-as-code) |
| `mlscan-redteam` (Job) | kata | isolation escape test (Stage 5) |
| ConfigMap `mlscan-harness`, `mlscan-samples`, `mlscan-deception*`, `mlscan-sinkhole`, `mlscan-redteam` | — | harness code, demo data, honeypot files, sinkhole server, redteam script |
| NetworkPolicy `default-deny-all`, `allow-dns-egress`, `sandbox-to-sinkhole`, `sinkhole-ingress`, `sandbox-to-testing-artifacts` | — | network isolation (Calico) |
| PSA `restricted` (namespace label) | — | prohibition of privileged pods |

**Artifact transport:** the file resides on the PVC of the testing service (`/artifacts`); the
sandbox Job downloads it from the Artifact server of the testing service (port **8090**) using a
one-time token. The per-scan ConfigMap transport is no longer used.

### 2.2 `mlscan-monitoring` — eBPF monitoring

| Object | Type | Purpose |
|--------|-----|-----------|
| `falco` (DaemonSet) | Falco 0.45.0, modern eBPF driver | host syscalls: exec/egress/write; rules `MLScan sandbox *` |

### 2.3 `mlscan-testing` — testing service (Component 2)

| Object | Type | Purpose |
|--------|-----|-----------|
| `mlscan-testing` (Deployment + ClusterIP Service :8080 + :8090) | stdlib HTTP | streaming ingestion of artifacts of any size, L1 (static analysis), launching the Job, Artifact server (8090, serves to the sandbox by token), collecting L2/L3, normalization, verdict, `/stats`; **writing the artifact to S3 (Garage)** under the key `sha256/<name>` with a deduplication check; mirroring metadata and findings into **PostgreSQL**; messages in the request language (RU/EN) |
| ServiceAccount `mlscan-testing` + Role/RoleBinding in `mlscan-sandbox` | RBAC | create/delete Jobs, get pods/logs in the sandbox |
| PVC `mlscan-testing-data` | hostpath 1Gi | scan records (`/data/scans/*.json`) |
| PVC `mlscan-artifacts` | hostpath 20Gi | uploaded models (`/artifacts/<scan_id>/<name>`) |
| ConfigMap `mlscan-poc-lib`, `mlscan-testing-code`, `mlscan-formats`, `mlscan-s3client`, `mlscan-pgclient`, `mlscan-authz`, `mlscan-i18n` | — | shared analysis (PoC), service code, format adapters, S3 and PG clients, authentication/authorization, localisation |

### 2.4 `mlscan-analytics` — analytics engine + UI (Component 3)

| Object | Type | Purpose |
|--------|-----|-----------|
| `mlscan-analytics` (Deployment + ClusterIP Service :8080; externally — Ingress `analytics.mlscan.local`) | stdlib HTTP | collection of results, scoring, Policy Engine, evidence (file + mirror in PostgreSQL), reports, web UI with a **RU/EN** language switcher, UI login (users/API keys), `/settings` page (global language; role `admin`) |
| PVC `mlscan-analytics-data` | hostpath 1Gi | `/data/evidence.jsonl` (hash-chain) |
| ConfigMap `mlscan-analytics-code`, `mlscan-policy`, `mlscan-authz`, `mlscan-pgclient`, `mlscan-i18n` | — | engine code, `policy.json`, authentication/authorization, PG client, localisation |

Dashboard performance: queries that reach the testing service (`/api/overview`, `/api/stats`)
are cached in analytics for 5 s (the testing service cache is 30 s and is invalidated when a new
scan is written). The UI renders the table as soon as `/api/overview` returns and the statistic
cards after the separate `/api/stats`, so the scan list appears in ~0.2 s.

### 2.5 `mlscan-integrations` — integrations (Stage 4)

| Object | Type | Purpose |
|--------|-----|-----------|
| `mlscan-integrations` (Deployment + ClusterIP Service :8080; externally — Ingress `integrations.mlscan.local`) | stdlib HTTP | Model Registry, CI/CD gate, SIEM export, threat-intel |
| PVC `mlscan-integrations-data` | hostpath 512Mi | `registry.json`, `events.jsonl` |
| ConfigMap `mlscan-integrations-code`, `mlscan-intel`, `mlscan-authz`, `mlscan-pgclient`, `mlscan-i18n` | — | service code, seed threat-intel, authentication/authorization, PG client, localisation (PG is connected for moving the registry out) |

### 2.6 `mlscan-ops` — operations (Stage 5)

| Object | Type | Purpose |
|--------|-----|-----------|
| `mlscan-ops` (Deployment + ClusterIP Service :8080; externally — Ingress `ops.mlscan.local`) | stdlib HTTP | Prometheus metrics, stack health, quality (TPR/FPR), SLA, retest, storage alerts (`/alerts`), language settings (`/settings`, `POST /settings/language`) |
| CronJob `mlscan-retest` | `*/30 * * * *` | continuous retest of the golden set |
| PDB `*-pdb` | — | PodDisruptionBudget for testing/analytics/integrations |
| ConfigMap `mlscan-ops-code`, `mlscan-golden`, `mlscan-golden-samples`, `mlscan-authz`, `mlscan-pgclient`, `mlscan-i18n` | — | code, golden labels and samples, authentication/authorization, PG client, localisation |
| Storage access | env `PGHOST…`, `GARAGE_ADMIN_URL/TOKEN` | reading DB sizes and Garage metrics for alerts |

### 2.7 `mlscan-data` — storages and service tasks (v2)

| Object | Type | Purpose |
|--------|-----|-----------|
| `garage` (StatefulSet + Services :3900 API, :3903 admin; PVC `data-garage-0` 800Gi) | Garage v1.0.1 | **S3-compatible object storage** of artifacts; keys `sha256/<name>`; admin API for metrics and keys |
| `postgres` (StatefulSet + Service :5432; PVC `data-postgres-0` 20Gi, backups in `mlscan-backups` 10Gi) | PostgreSQL 16 | relational storage (`artifacts`, `scans`, `findings`, `evidence`, `users`, `api_keys`, `audit_log`, `settings`, …); schema — `deploy/v2/db/10-schema.yaml`; append-only triggers on `evidence` and `audit_log` |
| `mlscan-ingest` (Deployment + Service :8080) | stdlib HTTP | streaming upload gateway to S3 with deduplication (for external suppliers), size control, audit |
| CronJob `mlscan-lifecycle` | `30 3 * * *` | **retention/TTL**: deletion of expired artifacts from S3, tombstones, quarantine cleanup |
| CronJob `mlscan-pg-backup` | `0 2 * * *` | PostgreSQL backup with restore verification |
| Secret `mlscan-s3`, `garage-secrets`, `mlscan-pg` | — | access to S3, the Garage cluster and PostgreSQL |
| ConfigMap `mlscan-s3client`, `mlscan-pgclient`, `mlscan-authz`, `mlscan-i18n`, `mlscan-pg-init`, `mlscan-lifecycle` | — | stdlib clients (SigV4, SCRAM), authorization, localisation, DB schema, maintenance tasks |

### 2.8 `mlscan-ingress` — external entry point (v2)

| Object | Type | Purpose |
|--------|-----|-----------|
| `mlscan-gateway` (Gateway) + VirtualServices | Istio | host-based routing of `analytics|integrations|ops|api.mlscan.local` to MLScan ClusterIP services |
| NetworkPolicy egress-allowlist | Calico | for platform namespaces: DNS + cluster CIDRs; external egress is prohibited |

### 2.9 `mlscan-build` — building the sandbox image

| Object | Type | Purpose |
|--------|-----|-----------|
| `mlscan-sandbox-build` (Job, Kaniko) | executor v1.23.2 | building the `mlscan-sandbox` image and publishing it to the in-cluster registry |
| ConfigMap `mlscan-sandbox-build` | — | `Dockerfile` of the build context |

Image: `python:3.12-slim` + **torch 2.14.1+cpu** + numpy, safetensors, onnxruntime, h5py,
gguf, joblib, dill, cloudpickle. Built without Docker on the host (Kaniko); the result is
`localhost:32000/mlscan-sandbox:v2` (for kubelet). The tag is set by an argument
(`bash deploy/sandbox-image/build.sh v2`) and passed to the testing service via
`SANDBOX_IMAGE`.

---

## 3. Network interaction diagram

```mermaid
flowchart TB
  subgraph EXT["External consumers"]
    CI["CI/CD (mlscan-gate.sh)"]
    BR["Browser / operator"]
  end
  subgraph IGW["istio-system"]
    GW["istio-ingressgateway :80 (NodePort 30217)"]
  end
  subgraph INT["mlscan-integrations"]
    INTG["mlscan-integrations :8080"]
  end
  subgraph ANA["mlscan-analytics"]
    ANAL["mlscan-analytics :8080"]
  end
  subgraph TST["mlscan-testing"]
    TEST["mlscan-testing :8080 + :8090"]
  end
  subgraph OPS["mlscan-ops"]
    OPSD["mlscan-ops :8080"]
  end
  subgraph SBX["mlscan-sandbox (PSA restricted)"]
    API["Kubernetes API"]
    JOB["sandbox Job / redteam Job (Kata microVM)"]
    SINK["sinkhole :8080 + tcp 4444/9001/1337"]
    DEC["deception files"]
  end
  subgraph MON["mlscan-monitoring"]
    FALCO["Falco (eBPF)"]
  end
  subgraph BLD["mlscan-build"]
    KAN["Kaniko Job"]
    REG["registry :32000"]
  end
  subgraph DATA["mlscan-data (v2)"]
    GAR["Garage S3 :3900 / admin :3903"]
    PG["PostgreSQL :5432"]
    ING["mlscan-ingest :8080"]
    LIF["lifecycle / pg-backup (CronJob)"]
  end
  NET["Internet"]

  BR -->|"Host analytics.mlscan.local"| GW
  CI -->|"Host integrations.mlscan.local"| GW
  GW -->|"VirtualService"| ANAL
  GW -->|"VirtualService"| INTG
  GW -->|"VirtualService"| OPSD
  GW -->|"VirtualService"| TEST
  INTG -->|"GET /api/scans :8080"| ANAL
  INTG -->|"POST /scans :8080"| TEST
  ANAL -->|"GET /scans :8080"| TEST
  TEST -->|"create Job, read pod logs (API 443)"| API
  API -.->|"schedules"| JOB
  JOB -->|"GET artifact :8090 (ALLOW)"| TEST
  JOB -->|"egress ALLOW http/tcp"| SINK
  JOB -.->|"egress DENY (default-deny)"| NET
  OPSD -->|"scans / sync / registry"| ANAL
  INTG -.->|"egress DENY (allowlist)"| NET
  DEC -.->|"mounted read-only"| JOB
  FALCO -.->|"host syscalls (runc); Kata guest invisible"| SBX
  KAN -->|"push image"| REG
  REG -.->|"image pull (kubelet)"| JOB
  TEST -->|"put artifact sha256/<name> (dedup)"| GAR
  TEST -->|"scans / findings (mirror)"| PG
  ANAL -->|"scans / findings / evidence (mirror)"| PG
  ING -->|"stream upload (gateway)"| GAR
  OPSD -->|"db size / garage metrics"| PG
  OPSD -->|"admin :3903 /metrics"| GAR
  LIF -.->|"retention / TTL"| GAR
```

**Directions and protocols:**
- External access — **the single entry point Istio Ingress Gateway** (HTTP NodePort `30217`),
  host-based routing `analytics|integrations|ops|api.mlscan.local`; MLScan services have no NodePort
  (ClusterIP).
- Internal calls — HTTP `:8080` via cluster DNS (`<svc>.<ns>.svc.cluster.local`).
- `TEST → Kubernetes API` — HTTPS `:443` (creating a Job, reading `pods/log`).
- `Kata-Job → testing:8090` — downloading ITS OWN artifact by token (allow);
- `Kata-Job → sinkhole` — the allowed channel; to the outside — deny (NetworkPolicy default-deny).
- `Falco` observes host syscalls; syscalls **inside the Kata microVM are invisible to it**
  (in-guest harness instrumentation works there).
- The sandbox image is built by Kaniko in `mlscan-build` and published to the in-cluster registry;
  kubelet pulls it when the Job is created.
- **Platform egress** — allowlist (deny-by-default + DNS + cluster CIDRs); external egress of
  services is prohibited.
- **Artifacts** — `TEST → Garage S3` (`sha256/<name>`, deduplication by key presence), a local
  copy on the PVC remains as a fallback; **metadata/findings/evidence** are mirrored to PostgreSQL.
- **Retention** — the CronJob `mlscan-lifecycle` deletes expired S3 objects, keeps tombstones
  and clears the quarantine; `mlscan-pg-backup` makes a DB backup with restore verification.

---

## 4. Network access model and policies

### 4.1 NetworkPolicy in `mlscan-sandbox` (Calico v3.29.3)

| Policy | Type | Effect |
|----------|-----|--------|
| `default-deny-all` | Ingress+Egress | all traffic denied by default |
| `allow-dns-egress` | Egress | DNS to `kube-dns` (UDP/TCP 53) |
| `sandbox-to-sinkhole` | Egress | `app=mlscan-sandbox → app=sinkhole` (any ports) |
| `sinkhole-ingress` | Ingress | into sinkhole — only from `app=mlscan-sandbox` |
| `sandbox-to-testing-artifacts` | Egress | `mlscan-sandbox → mlscan-testing:8090` (downloading ITS OWN artifact by token) |

Verified: `1.1.1.1:443` and `example.com:80` → **DENY** (timeout), `sinkhole:8080` → **OK**.

### 4.2 External exposure

The single entry point is the **Istio Ingress Gateway** (external MLScan services are ClusterIP):

| Host (Host header) | Gateway | Purpose |
|--------------------|---------|-----------|
| `analytics.mlscan.local` | `mlscan-ingress/mlscan-gateway` | web UI + JSON API |
| `integrations.mlscan.local` | the same | gate/registry/SIEM/intel |
| `ops.mlscan.local` | the same | metrics/quality/SLA |
| `api.mlscan.local` | the same | testing API |

Gateway: `istio-ingressgateway` (ns `istio-system`), HTTP NodePort **30217** (HTTPS 30921).
The services `mlscan-testing` (ClusterIP :8080+:8090) and `sinkhole` are internal.

### 4.3 Egress control (migration from "open" egress to allowlist)

| Namespace | Egress policy | Allowed |
|-----------|-----------------|-----------|
| `mlscan-testing` | `mlscan-egress` | DNS; cluster CIDRs (8080/8090/443); Kubernetes API (`<API_ENDPOINT>`) |
| `mlscan-analytics` | `mlscan-egress` | DNS; cluster CIDRs (8080/8090) |
| `mlscan-integrations` | `mlscan-egress` | DNS; cluster CIDRs (8080) |
| `mlscan-ops` | `mlscan-egress` | DNS; cluster CIDRs (8080) |
| `mlscan-sandbox` | `default-deny-all` + allow | DNS; sinkhole; `testing:8090` (artifact) |

External egress of platform services is **prohibited** (verified: `1.1.1.1:443 → DENY`).
Point access to external resources — via an FQDN allowlist (Calico) or an Egress Gateway (planned).

---

## 5. End-to-end flow (scan + gate)

```mermaid
sequenceDiagram
  participant CI as CI/CD
  participant INT as Integrations
  participant TS as Testing Service
  participant K8S as K8s API
  participant SB as Sandbox Job (Kata)
  participant AN as Analytics
  participant OP as Ops

  CI->>INT: POST /gate/scan (artifact)
  INT->>TS: POST /scans (artifact)
  TS->>TS: L1 static analysis
  TS->>DATA: put artifact sha256/<name> (S3 Garage, dedup)
  TS->>DATA: mirror scan/findings (PostgreSQL)
  TS->>K8S: create Job
  K8S->>SB: schedule (kata, restricted)
  SB->>TS: GET /a/<scan_id>/<token>/<name> (artifact, :8090)
  SB->>SB: load under audit-hooks (L2/L3)
  SB-->>TS: pod logs (MLSCAN_RESULT_JSON)
  TS->>K8S: delete Job
  TS-->>INT: normalized findings + verdict
  INT->>INT: registry + threat-intel + gate decision
  INT-->>CI: decision allow | block | review
  AN->>TS: poll /scans (sync)
  AN->>AN: scoring + policy + evidence hash-chain
  AN->>DATA: mirror evidence/findings (PostgreSQL)
  OP->>AN: /api/scans, /quality, /alerts
  OP->>INT: /registry, /events
  OP->>TS: POST /retest (CronJob */30)
```

---

## 6. Storages, configuration, RBAC

| Component | Storage | What is stored |
|-----------|-----------|--------------|
| **S3 (Garage), ns `mlscan-data`** | object (`data-garage-0`, 800Gi), `sha256/<name>` | **artifacts** (model bodies) for testing/ingest; deduplication by key |
| **PostgreSQL, ns `mlscan-data`** | StatefulSet + PVC (`data-postgres-0` 20Gi; backups in `mlscan-backups` 10Gi) | `artifacts`, `scans`, `findings`, `evidence`, `users`, `api_keys`, `audit_log`, `uploads`, `connections`, `settings` |
| testing | PVC `mlscan-testing-data` (1Gi), `mlscan-artifacts` (20Gi) | `/data/scans/<id>.json`; local copies of artifacts (fallback if S3 is unavailable) |
| analytics | PVC `mlscan-analytics-data` (1Gi) | `/data/evidence.jsonl` (hash-chain) |
| integrations | PVC `mlscan-integrations-data` (512Mi) | `/data/registry.json`, `/data/events.jsonl` |
| ops | — (stateless) | state in memory |

Configuration — ConfigMaps (service code, `policy.json`, `intel.json`, `golden.json`, harness,
deception, sinkhole, and also the shared modules `mlscan-authz`, `mlscan-pgclient`, `mlscan-s3client`,
`mlscan-i18n`). Evidence integrity attestation — `deploy/stage5/60-attest.sh` (HMAC-SHA256).

### 6.1 S3 (Garage) layer — artifacts

**Object storage** `garage` (ns `mlscan-data`, S3 API `:3900`, admin `:3903`).

- The object key is `sha256/<filename>`: content-addressed, so re-uploading the same
  file is **deduplicated** (key existence check before upload).
- Writers: the testing service (`POST /scans/upload`) and the gateway `mlscan-ingest` (`POST /upload`,
  for external suppliers). Readers: the testing service (serving the artifact to the sandbox by a
  one-time token) and `mlscan-lifecycle` (deletion by TTL).
- The client is the stdlib `s3client.py` (SigV4, streaming), delivery to the sandbox — via the
  testing service (port 8090), so the sandbox's network access is not expanded.
- Retention: the CronJob `mlscan-lifecycle` (`30 3 * * *`) deletes expired objects,
  keeps `artifact_deletions` (tombstones) and clears the quarantine. Inter-zone replication
  (RF) — a Garage operational parameter (in single-node RF=1).

### 6.2 PostgreSQL layer — metadata, evidence, access

**There is no DBMS in the base contour (Stages 0–5); in v2 it was added** and is used by the services
as the primary relational storage (schema — `deploy/v2/db/10-schema.yaml`, client —
stdlib `pgclient.py` with SCRAM authentication).

| Table | Who writes | Content |
|---------|-----------|-----------|
| `artifacts`, `artifact_fingerprints` | testing, analytics | deduplicated artifacts (sha256, size, format, `s3_key`), fingerprints |
| `scans`, `findings` | testing (immediately), analytics (mirror) | status/stages/verdict/reason, normalized findings |
| `evidence` | analytics | **append-only hash-chain**: `prev_hash`, `hash`, `payload` |
| `users`, `api_keys` | access management | UI users (PBKDF2 hashes) and API keys (hashes), roles |
| `audit_log`, `uploads`, `connections` | all services (via `authz`) | action audit, upload log, HTTP connection log |
| `settings` | admin (`/settings` page / API) | system settings, incl. the **global language** (`language`) |
| `policies`, `decisions` | — | the schema is ready; in practice the policy is set by `policy.json` (ConfigMap) |

Integrity: `evidence` and `audit_log` have triggers prohibiting `UPDATE/DELETE`
(append-only "at the DB level"), in addition to the hash chain. Backup —
the CronJob `mlscan-pg-backup` (`0 2 * * *`) with restore verification.

### 6.3 File storages (retained)

- **Analytics:** `/data/evidence.jsonl` — append-only JSONL; a line = `{"prev","hash","record"}`,
  where `hash = sha256(prev + json(record))` → **tamper-evident hash chain** (read at
  startup into the in-memory index `scan_id → record`; control — `GET /api/evidence/verify`).
  In PostgreSQL the same evidence is mirrored (double write).
- **Testing:** `/data/scans/<id>.json` — scan card; `/artifacts/<scan_id>/<name>` —
  local copy of the artifact (fallback when S3 is unavailable).
- **Integrations:** `/data/registry.json` (registry `sha256 → entry`) and `/data/events.jsonl`
  (append-only gate/SIEM events).

**Actual state (at the time of update):** `scans=1442`, `findings=7399`,
`evidence=1422`, `artifacts=70`, `audit_log=6302`, `users=2`, `settings=1` (language);
`/data/evidence.jsonl` ≈ 3.7 MB.

### 6.4 RBAC

- The only cross-namespace link is the SA `mlscan-testing` (ns `mlscan-testing`) with a Role in
  `mlscan-sandbox` (Jobs/ConfigMaps create·delete·get, pods/logs get). The other services
  work without access to the Kubernetes API.
- Access to the API/UI — `authz` (`mlscan-authz`): static API keys from the Secret `mlscan-keys`
  (roles `admin`/`ci-reader`/`service`) and UI users from the `users` table (session in a cookie);
  role checks on endpoints, audit in `audit_log`.

---

## 7. Trust boundaries and isolation

| Zone | Trust | Isolation |
|------|---------|----------|
| `mlscan-sandbox` (artifact execution) | **untrusted** | Kata 3.32.0 (microVM), PSA restricted, non-root 65532, read-only rootfs, drop ALL, seccomp, limits, default-deny egress, deception |
| `mlscan-monitoring` | trusted (monitoring) | DaemonSet, modern eBPF |
| `mlscan-testing` / `mlscan-analytics` / `mlscan-integrations` / `mlscan-ops` | trusted | PSA restricted, non-root, read-only rootfs, drop ALL, no excess privileges |
| `mlscan-data` (S3/Garage, PostgreSQL, ingest) | trusted | PSA restricted, StatefulSet PVC, access via Secret; the artifact is **not executed** |
| `mlscan-ingress` (Gateway, VirtualServices, egress policies) | trusted (configuration) | Istio/Calico objects; executes no code |

The artifact is transferred to the sandbox **without shared directories and without content in the manifests**:
the Job downloads its file from the Artifact server of the testing service (`:8090`) by a one-time
token; platform secrets (SA tokens, access to S3/DB) are not mounted into the sandbox.

---

## 8. Ports and internal addresses (DNS)

| Service | DNS (inside the cluster) | Port |
|--------|----------------------|------|
| testing | `mlscan-testing.mlscan-testing.svc.cluster.local` | 8080 (API), 8090 (artifact) |
| analytics | `mlscan-analytics.mlscan-analytics.svc.cluster.local` | 8080 |
| integrations | `mlscan-integrations.mlscan-integrations.svc.cluster.local` | 8080 |
| ops | `mlscan-ops.mlscan-ops.svc.cluster.local` | 8080 |
| sinkhole | `sinkhole.mlscan-sandbox.svc.cluster.local` | 8080, 4444, 9001, 1337 |
| Garage (S3) | `garage.mlscan-data.svc.cluster.local` | 3900 (S3 API), 3903 (admin) |
| PostgreSQL | `postgres.mlscan-data.svc.cluster.local` | 5432 |
| ingest (S3 gateway) | `mlscan-ingest.mlscan-data.svc.cluster.local` | 8080 |

External access — Ingress: `analytics|integrations|ops|api.mlscan.local` via `:30217`.
Main endpoints: `/scans`, `/scans/upload?lang=` (testing),
`/`, `/artifact/<id>`, `/lang`, `/settings`, `/settings/language`, `/api/scans|/api/overview|
/api/stats|/reports|/policy` (analytics),
`/registry|/gate|/gate/scan|/events|/export/cef|/intel` (integrations),
`/metrics|/health/stack|/quality|/sla|/alerts|/settings|/settings/language|/retest` (ops),
`/upload` (ingest).

The response language is selected as follows: `?lang=ru|en` → cookie `mlscan_lang` → `X-MLScan-Lang`/
`Accept-Language` → the global setting (`settings` table) → `MLSCAN_LANG` at startup.

---

## 9. Observability

- **In the sandbox:** audit-hooks harness (L2/L3: files/processes/network/ctypes, state diff) —
  also works inside Kata.
- **Host:** Falco (modern eBPF), rules `MLScan sandbox *` (exec/egress/write) for runc pods.
- **Stack:** `/metrics` (Prometheus `mlscan_*`), `/health/stack`, `/quality` (TPR/FPR), `/sla`,
  `/alerts` (state of PostgreSQL/Garage and evidence integrity — messages in the request language).

Verified metrics: red-team — 7/7 PASS; quality — TPR=1.0, FPR=0.0 (tp=7, fp=0, tn=2, fn=0);
evidence-chain — ok.

---

## 10. Limitations (single-node) and growth points

- **GPU:** `nvidia.com/gpu: 0` — GPU isolation was not applied; the GPU pod template is ready after
  installing the NVIDIA device plugin.
- **Scaling:** services with RWO-PVC and file-based state do not scale horizontally correctly;
  RWX/external DB and stateless pods are needed. The Ops service is stateless.
- **Attestation:** HMAC (for prod — Sigstore/cosign, image signing).
- **eBPF in Kata:** host-eBPF does not see the guest's syscalls — an in-guest sensor is needed (the
  harness already performs this role).
- External SIEM/tickets — via `/export/cef` and `/events` (integration on the consumer side).
- **Dynamic analysis:** torch/numpy models and Python 2-style pickle (`__builtin__`) are now
  executed in the sandbox (`mlscan-sandbox` image + harness compatibility).
- **Storages (v2, implemented):** artifacts — in **S3 (Garage)** with deduplication and
  retention/TTL (CronJob `mlscan-lifecycle`); metadata/findings/evidence — in **PostgreSQL**
  (+ append-only triggers, backup with restore verification). Local PVCs are retained as a
  fallback and as the source of hash-chain evidence; the analytics file storage is still a
  **single writer** (`replicas=1`), and there are no arbitrary SQL queries from the UI.
- **Access (v2, implemented):** authentication/authorization (API keys from a Secret + UI users
  in the DB + session), roles `admin`/`ci-reader`/`service`, audit in `audit_log`. Not implemented:
  OIDC/Keycloak and mTLS (Istio sidecar not enabled).
- **Storage fault tolerance:** single-node — Garage without replication (RF=1), PostgreSQL without
  a replica; DR/backup is moved to a CronJob and external procedures.
- **GPU** — still unavailable (see above).
- **Localisation:** the UI, service messages, findings and reports are localised; canonical
  identifiers (`verdict`, `severity`, `policy.action`, `check_id`) are not translated.

---

## 11. Related documents

- `../../Concept.md` — concept and target architecture.
- `./01-threat-checklist.md`, `./02-testing-strategy.md`, `./03-isolation.md`, `./04-risk-analysis-decision.md`, `./05-architecture.md`, `./06-implementation-plan.md`.
- `../../deploy/stage1…stage5/README.md`, `../../deploy/sandbox-image/README.md`, `../../deploy/ingress/README.md` — operational descriptions of the stages, the sandbox image and the migration to Ingress/Egress.
- `./08-testing-guide.md` — what to test and where to connect.
- `./09-formats-and-backdoors-analysis.md` — analysis of other ML/AI formats and types of backdoors.
- `./10-plan-new-formats.md` — plan of enhancements for new formats.
- `./11-target-architecture-v2.md` — target architecture v2 (large models, S3/DB, speed).
- `./12-i18n.md` — localisation of the UI and messages (RU/EN): language selection levels, global setting.
- `../../deploy/v2/README.md` — v2 (S3/PostgreSQL/AuthN+audit/observability/backup/lifecycle/detectors).
- `../../deploy/i18n/README.md` — localisation module; `../../deploy/ingress/README.md` — Ingress/Egress.
- `../../README.en.md`, `./` — English-language versions of the documentation.
- `../../poc/README.md` — single-file PoC.
