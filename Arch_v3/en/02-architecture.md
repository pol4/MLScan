# 02. v3 architecture

Full description: `../02-architecture.md` (RU). This is the English core.

## 1. Planes

```
        ┌────────────────────────── Edge (TLS/mTLS) ───────────────────────────┐
Client ─▶│  Upload Edge (presigned/multipart)   API/UI (OIDC)   Gate (CI/SIEM)   │
        └───────────────┬──────────────────────────────┬──────────────────────┘
                        ▼                              ▼
             ┌─────────────────────── Control plane ────────────────────────┐
             │  Tenant/Quota  Scheduler/Queue  Policy  Scan Orchestrator    │
             └───────────┬───────────────────────────────┬──────────────────┘
                         ▼                               ▼
  ┌──────────── Data plane (distributed S3) ───────┐   ┌──── Evidence/Registry ────┐
  │ Storage nodes (shards, RF≥2/EC, NVMe+cold)     │   │ PostgreSQL + WORM bucket  │
  └───────────┬────────────────────────────────────┘   └───────────────────────────┘
              │ range-read (parallel)
              ▼
  ┌──────────────────────── Analysis plane ─────────────────────────┐
  │  Static engine (streaming, index/sampling)   Archive walker     │
  │  Node-local NVMe cache   Sandbox (Kata, sampled dynamic)        │
  │  Parser-sandbox (fuzzing)                                       │
  └─────────────────────────────────────────────────────────────────┘
```

## 2. Components

- **Edge**: Upload Edge (presigned multipart, tenant/quota checks, audit); API/UI (OIDC); Gate (CI/SIEM).
- **Control plane**: Tenant/Quota; persistent Scheduler/Queue; Policy engine (versioned/signed);
  Scan Orchestrator (strategy, budgets, aggregation, coverage).
- **Data plane**: distributed S3 (≥3 nodes, sharding, RF≥2/EC, hot NVMe + cold tier); content-addressed
  shared pool + tenant refs; node-local NVMe read-through cache.
- **Analysis plane**: static engine (streaming, index-driven, sampling); archive walker (member
  streaming, nested, index, member-workers); Kata sandbox for sampled dynamic; parser-sandbox.
- **Registry/Evidence**: PostgreSQL; WORM evidence with HMAC chain and anchoring.

## 3. Deployment diagram

See the Mermaid deployment diagram in the RU document (`../02-architecture.md` §3); it mirrors this
component list (edge/control/data/analysis/platform).

## 4. State diagrams

Russian original carries two Mermaid state diagrams: (a) upload+analysis of a 1 TB model, and
(b) comprehensive analysis of a 1 TB archive with all formats (`../02-architecture.md` §4–5).

## 5. Invariants

1. Analysis reads object ranges from S3; full download only within sandbox limits.
2. Incompleteness (unread ranges/members/skipped dynamic) is recorded in coverage and affects the
   verdict (`Inconclusive`).
3. Evidence is append-only with HMAC and WORM anchoring.
4. Every object/scan belongs to a tenant; quotas and SLOs are per-tenant.
5. Images/configs/policies are versioned and signed; analysis is reproducible by version.

## 6. LLM inference testing (separate test type)

Large LLMs are tested by running their **inference engine (container image) together with the model**
inside an isolated **Kata** microVM with a **custom kernel that includes eBPF/Tetragon**; the verdict
comes from observing runtime behavior (syscalls/exec/net/file/mmap) and from **OpenAI-API probes**
(configurable prompt list evaluated against reference answers). Requires a dedicated resource/GPU node
pool. Full design: `../16-llm-inference-testing.md` (RU).
