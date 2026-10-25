# 00. v3 overview

## 1. Goal

Full support for ML models and archives of models/other artifacts of **1 TB and above**: ingest,
storage, streaming analysis (static + sampled dynamic), member-wise archive analysis, trustworthy
verdict, multi-tenancy, production-grade operations (HA, DR, SLO).

## 2. Why v3

v2 (`../../Arch_v2/03-v2-limitations.md`) proved the concept but its key traits do not scale to TB:
single-node data-plane (RF=1, ~40 MB/s ingest), two-hop/materializing data path, archive traversal
capped at 128 MiB/archive, "whole-model-only" dynamic analysis, shallow multi-tenancy.

v3 changes three things: the **data-plane becomes distributed and fast**; analysis reads **only the
needed object ranges** from S3; archives are traversed **streaming, member by member**.

## 3. Principles

1. Data is never fully materialized (range-read / mmap cache); full download only within sandbox limits.
2. Ingest is **direct-to-S3 by default**; parallel/resumable with quotas.
3. Content-addressed shared pool + tenant refs (cross-tenant dedup, isolation via ACL/quota/KMS).
4. Explicit **coverage**; incompleteness yields `Inconclusive`.
5. Secure by default (TLS/mTLS, short presigned TTL, Kata sandbox, deny-by-default egress, WORM evidence).
6. Multi-tenancy is first-class (quotas, fair-share, per-tenant SLO).
7. Everything versioned/reproducible (detectors/policies/images, GitOps).
8. Honest limits (see `14-limitations.md` in the RU set).

## 4. v2 → v3 (summary)

| Area | v2 | v3 |
|------|----|----|
| Data-plane | 1 Garage node, RF=1 | ≥3 nodes, RF≥2/EC, sharding, tiering |
| Ingest | ~40 MB/s/node | ≥1 GB/s/node, aggregate ≥5 GB/s, NVMe |
| Data path | 2 hops, materialization | direct-to-S3, streaming range-read |
| Static | 64 MiB prefix | streaming/incremental index+sampling |
| Archives | 128 MiB/archive cap | member streaming 1 TB+, index, depth budget |
| Dynamic | whole-model only | sampled slices/members with budgets |
| Multi-tenant | prefix, no quotas | quotas, fair-share, KMS, isolation |
| Transport | plaintext S3 passthrough | TLS/mTLS, short presigned TTL |
| Reliability | single replica, manual ops | HA, queues/autoscale, DR, GitOps |

See the RU set for details and diagrams: `../02-architecture.md`, `../03-data-plane.md`,
`../04-ingest.md`, `../05`–`07-analysis-*`, `../08-security-isolation.md`, `../09-observability-sla.md`,
`../10-deployment.md`, `../11-migration-v2-to-v3.md`, `../12-testing-strategy.md`, `../13-formats.md`,
`../14-limitations.md`, `../15-implementation-plan.md` (also mirrored here).
