# 15. v3 implementation plan (English core)

Full plan: `../15-implementation-plan.md` (RU). Rule per phase (as in v2): **(1)** update/add tests →
**(2)** implement → **(3)** run unit + e2e + UI + perf, including **workstation (ARM) tests** →
**(4)** fix to green, then proceed.

## Phases

| Phase | Topic | Key outcomes | Reqs |
|-------|-------|--------------|------|
| P0 | Data-plane | distributed S3 (≥3 nodes, RF≥2/EC), shared pool + refs, range-get, TLS egress for S3 | F1,F8,N1,N2,N7 |
| P1 | Ingest v3 | TLS presigned, quotas/fair-share, adaptive parts, DB-persisted resume, import | F2,F3,F9 |
| P2 | Control plane | tenants/quotas, persistent queue, orchestrator, policy versioning | F7,F11 |
| P3 | Static v3 | index-driven streaming, sampling, coverage | F5,N3,N4,N9 |
| P4 | Archives v3 | range-based index, member walk, nesting, member index | F4,N5 |
| P5 | Dynamic v3 | slice selector, sampled dynamic, budgets | F6,N10 |
| P6 | Security/evidence | TLS/mTLS, KMS, WORM anchoring, SBOM/admission | F12,N7 |
| P7 | Observability/SLO | per-tenant metrics, tracing, dashboards, alerts, capacity | N1–N10 |
| P8 | HA/DR/GitOps | ≥2 replicas, DR replication/failover, GitOps | N6,N7 |
| P9 | Migration v2→v3 | dual-write, object/evidence migration, cutover | F10,F11 |
| P10 | Docs/finalization | docs refresh, reports, acceptance | — |

## Order

```
P0 ─▶ P1 ─▶ P3 ─▶ P4 ─▶ P5
        └─▶ P2 ─▶ P6 ─▶ P7 ─▶ P8 ─▶ P9 ─▶ P10
```

## Success metrics

Requirements N1–N11 (`../01-requirements.md`) and Definition of Done (`../12-testing-strategy.md`).

## Risks

S3 engine choice (prototype in P0, load-tested); streaming parser complexity (parser-sandbox + fuzzing);
archive performance (index + parallelism + budgets + cache); data migration (dual-write + reconcile,
keep v2 until stable); operational complexity (GitOps, SRE practices).
