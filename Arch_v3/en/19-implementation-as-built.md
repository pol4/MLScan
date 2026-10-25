# 19. v3 implementation status (as-built)

Summary of the sequential implementation of `../15-implementation-plan.md` on the current stand
(single-node microk8s). Code — `deploy/v3/**` (+ `deploy/stage2` changes); tests — `tests/**`.

All phases P0–P10 and L0–L4 are implemented and covered by unit/e2e/browser tests to the extent
possible on a single node:

- unit `tests/v3`: 148 OK; `tests/s3`, `tests/formats`: OK.
- browser UI (puppeteer): kind/promptset/upload — OK.
- e2e on real services (S3/Garage, PostgreSQL): range, object_refs, import, quota, resume-restart,
  static_stream, archive_walk, slice_selector, security_evidence, v3_metrics, ha_leader, migration,
  binding, registry_images, llm_env (Kyverno admission), llm_events, promptset, gate_attest — OK.
- multi-node S3 prototype: 3 Garage nodes, RF=2, durability on node loss — OK.

Items requiring target hardware (multi-node/GPU/custom kernel) are explicitly listed in
`../15-implementation-plan.md` §7: Harbor+cosign/SBOM, real in-guest Tetragon, trusted judge model,
domain→class editor, WORM/TSA anchoring, multi-node HA/DR, GitOps controller, ONNX/HDF5/GGUF index
adapters, and full scan-flow integration. Each is implemented as far as the stand allows, with
interfaces and a plan for the remainder.

Run: `python3 -m unittest discover -s tests/v3`; browser: `bash tests/ui/run_ui_tests.sh`;
e2e: `bash tests/e2e/<name>.sh`.
