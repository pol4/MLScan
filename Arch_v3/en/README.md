# Arch_v3 — MLScan target architecture for 1 TB+ artifacts

Third architecture version: **full support for ML models and archives of models/artifacts sized 1 TB
and above**. Removes v2 limits (`../../Arch_v2/03-v2-limitations.md`) via a scalable S3 cluster,
streaming analysis straight from storage, member-wise archive traversal, sampled dynamic analysis,
strict multi-tenancy and secure transport.

> Design documents; the plan is `15-implementation-plan.md`. The deployed system is v2 (`deploy/v2`).
> Future development follows v3.

Full RU set: `../README.md`. Key docs in English: `00-overview.md`, `02-architecture.md`,
`15-implementation-plan.md`.

Engine-image provenance/storage: RU `../17-engine-images-and-provenance.md`.
