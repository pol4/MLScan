[Русский](./START.md) | **English**

# MLScan — about the project (introductory article)

**MLScan — a system for security (maliciousness) analysis of models and data used in ML/AI.**

The project is focused not on a single format, but on a **class of tasks**: to determine whether an
ML/AI artifact contains a malicious, dangerous or uncontrolled component — and to give a
reproducible, provable conclusion about it.

---

## What is analyzed

- **Executability at load time.** Many ML/AI formats are capable of executing arbitrary code
  during deserialization or parsing (pickle and its derivatives, `Lambda` layers, custom
  ops/handlers, templates, etc.).
- **Backdoors of various kinds:** code execution, **weight trojans** (triggered,
  clean-label, "dormant", quant-activated), backdoors in the tokenizer/graph/format,
  **steganography** (metadata, least significant bits, trailing data, polyglots),
  **prompt-injection "in data"** (model/dataset cards, chat templates, tool/MCP schemas).
- **Malfunction and information disclosure:** leaks of PII/secrets, model inversion,
  guardrail bypass, DoS/resource exhaustion.
- **Integrity and provenance:** weight substitution, typosquatting, dependency confusion,
  absence of signature/SBOM.

---

## How it all started

The project started with a **small PoC** — a single Python file `poc/mlscan_poc.py` that
analyzed models **in pickle format** and relied only on the standard library and a
pre-installed Docker. The PoC immediately implemented **three verification methods**:

1. **Static analysis** — parsing of pickle (opcodes, globals, dangerous callables) without execution.
2. **Dynamic analysis** — deserialization in isolation with full observation (files, processes, network, ctypes).
3. **Behaviour** — load effects, state tampering, introspection and probing of the object.

On its basis, a **system for pickle** was deployed, consisting of three components (sandbox, testing
service, analytics engine with UI), and then integrations and the operational layer.

---

## Why it scales to other formats

The architecture was initially designed to be **format-agnostic**:

- **Layered verification model (L0–L4):** integrity → static analysis → dynamic analysis in the sandbox →
  behavioural tests → red-team. A new format = a new "format adapter" at levels L1/L2,
  without rebuilding the core.
- **Unified contract of findings and verdict** (`Normalized Finding`, scoring, Policy Engine) —
  rules and policies do not depend on a specific format.
- **Isolation "by default"** (Kata microVM, network and file restriction, deception) —
  applicable to any executable/parsable artifact.
- **Evidence base** (evidence with a hash-chain) and reports JSON/Markdown/SARIF — common.
- **Extensibility:** format adapters, detector rules, probe sets are added by plugins.

Therefore, the transition from pickle to SafeTensors/ONNX/HDF5/GGUF/model-as-code/datasets, etc. —
is an **expansion of the set of adapters and rules**, not a change of architecture.

---

## Current description of the system (pickle format)

**Implemented architecture (as-built):** [`docs/07-implemented-architecture.md`](./docs/en/07-implemented-architecture.md) —
component composition (9 namespaces), network interaction diagram (Ingress/Egress), data flows,
v2 storages (S3/PostgreSQL), authentication/authorization, RU/EN localisation.

Additionally:
- Concept and target architecture — [`Concept.md`](./Concept.en.md), [`docs/05-architecture.md`](./docs/en/05-architecture.md)
- Risk checklist — [`docs/01-threat-checklist.md`](./docs/en/01-threat-checklist.md)
- Testing strategy (L0–L4) — [`docs/02-testing-strategy.md`](./docs/en/02-testing-strategy.md)
- Isolation — [`docs/03-isolation.md`](./docs/en/03-isolation.md)
- Scoring and decision-making — [`docs/04-risk-analysis-decision.md`](./docs/en/04-risk-analysis-decision.md)
- Implementation plan — [`docs/06-implementation-plan.md`](./docs/en/06-implementation-plan.md)
- Test guide (what to check and where to connect) — [`docs/08-testing-guide.md`](./docs/en/08-testing-guide.md)
- PoC — [`poc/README.md`](./poc/README.md)

---

## Analysis of other formats and types of backdoors

**What else needs to be checked for security (ML/AI formats and backdoors):**
[`docs/09-formats-and-backdoors-analysis.md`](./docs/en/09-formats-and-backdoors-analysis.md)

The document covers: weight containers (SafeTensors, HDF5, Keras), model-as-code (`.mar`,
MLflow, `trust_remote_code`), graphs/compiled (ONNX, SavedModel, TFLite, TensorRT,
OpenVINO, CoreML), edge/quant (GGUF/GGML), data/datasets (Arrow/Parquet/WebDataset/Zarr),
tokenizers and prompt artifacts, configs/cards, archives/packages, indexes, agent/MCP artifacts;
as well as a **taxonomy of backdoors** (code, weights, tokenizer/graph, steganography, prompt-injection,
supply chain, runtime, GPU) with indicators and detection methods.

---

## Target architecture v2 (large models)

The next-version project (S3 storage, DBMS, authentication/audit, loading and analysis of
very large models) — [`docs/11-target-architecture-v2.md`](./docs/en/11-target-architecture-v2.md).

## Plan of expansion to other formats

Roadmap of improvements (waves, tasks, readiness criteria) —
[`docs/10-plan-new-formats.md`](./docs/en/10-plan-new-formats.md).

## Status

The PoC and the system for pickle are **implemented and deployed** (cluster `<CLUSTER>`): a sandbox on a
Kata microVM, a testing service with streaming model loading and progress, analytics with UI
and statistics, integrations (registry/CI-gate/SIEM), operational layer (metrics/quality/
retest/red-team), Ingress/Egress. Expansion to other formats is by the waves described in the
analysis document.
