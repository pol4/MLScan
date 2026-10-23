# 14. Security review of the MLScan architecture and code + remediation plan

[Русский](../14-security-review.md) | **English**

This document answers two questions:

1. **Can MLScan become a launchpad for attacks on other systems** (the cluster, neighbouring projects,
   external hosts) - i.e. be used as a weapon rather than as an analysis tool.
2. **Can MLScan stop being a trustworthy source** of information about artefact safety - i.e. report a
   false "Safe", forge findings/evidence/policy, or degrade so much that its conclusions are worthless.

It ends with a **remediation plan** (P0 - immediately, P1 - next sprint, P2 - planned).
The as-built architecture and trust boundaries are in [`07-implemented-architecture.md`](./07-implemented-architecture.md),
isolation in [`03-isolation.md`](./03-isolation.md), deployment levels in [`13-deployment-plan.md`](./13-deployment-plan.md).

---

## 1. Trust boundaries (summary)

| Zone | Trusted | Untrusted |
|------|---------|-----------|
| Sandbox (`mlscan-sandbox`, Kata microVM) | harness code (ours) | **the artefact and anything it executes** |
| Trusted zone (`testing`, `analytics`, `ops`, `integrations`, `data`) | service code, DB, S3 | **input data** (artefacts, their metadata, names, reports) |
| Shared cluster | `kata`, Istio, registry, `kube-*` | our namespaces and objects |
| External environment (CI, analyst, browser) | browser, API clients | the network up to ingress |

Invariants the system must provide:

* **I1.** The artefact is never executed in the trusted zone.
* **I2.** The sandbox cannot initiate network connections to foreign systems (only sinkhole/DNS).
* **I3.** The verdict and findings reflect what was actually observed; incompleteness is reported as
  `Inconclusive`, never as `Safe`.
* **I4.** Evidence and decisions cannot be changed unnoticed.
* **I5.** Compromising one service does not grant control over the cluster or affect other projects.

---

## 2. Attack scenarios

### A. MLScan as a launchpad

| # | Scenario | Mechanics | What already stops it | Residual risk |
|---|----------|-----------|-----------------------|---------------|
| A1 | **DNS tunnel / C2 from the sandbox** | the payload resolves external names through `kube-dns` (egress to port 53 is allowed) and encodes data in DNS queries | outbound TCP/UDP to the internet is denied (default-deny) | medium: DNS is allowed for everyone and resolves external names |
| A2 | **Cluster overload via scan flood** | mass uploads -> a storm of sandbox Jobs (node CPU/RAM/disk) affecting neighbouring projects | per-Job limits, `ephemeral-storage`, service PDBs | high: no namespace or per-client quotas |
| A3 | **Overloading the trusted zone with an artefact** | zip bomb (1 KB of deflate -> GB), thousands of findings, a huge JSON | bomb detector (`FMT-04`), 64 MB file read cap | medium: archive member decompression is not capped (see F-B3) |
| A4 | **Sandbox image substitution** | our image is referenced by a **tag, not a digest**; the in-cluster registry has no auth -> swapping `mlscan-sandbox:v4` yields executable code inside the sandbox (and enables result forgery) | kata, read-only FS, network denial inside | high: results become untrustworthy |
| A5 | **Lateral movement from the trusted zone** | platform namespace egress allows the **whole cluster CIDR** on ports 443/8080/8090/3900/5432 -> a compromised service reaches the API server and other projects' HTTPS services | none | high |
| A6 | **Kubernetes API from the testing service** | SA `mlscan-testing` can **create Jobs in `mlscan-sandbox`** -> arbitrary image/command -> code execution in the cluster and resource consumption | PSA restricted, no token in the sandbox, no secrets in the sandbox namespace | medium |
| A7 | **Sinkhole as an "internal service"** | the payload "attacks" the sinkhole (the only reachable address) | the sinkhole only accepts connections and is isolated | low |

### B. Compromise of the trusted zone through untrusted input

| # | Scenario | Mechanics | Residual risk |
|---|----------|-----------|---------------|
| B1 | **L1 parsing of the artefact** | static analysis runs inside the testing service: zip/tar/XML/YAML/ONNX/GGUF/HDF5/protobuf-like data | low/medium: our code is Python (memory-safe) but the parsers were never fuzzed |
| B2 | **Path traversal via the artefact name** | `name` from `?name=` | **closed**: `os.path.basename()` on upload and on serving |
| B3 | **Bomb inside a zip** | `zf.read(member)` without a cap on the **decompressed** size (the 8 MB limit covers only nested archives) | medium: service OOM (DoS), not RCE |
| B4 | **Finding explosion** | a pickle with thousands of globals -> tens of thousands of findings -> PG/JSON/UI bloat | medium: no cap on the number/size of findings |
| B5 | **ReDoS in our own regexes** | regexes for `PIPE_TO_SHELL`, `CSV_FORMULA`, Jinja/templates | low: quantifiers are bounded (`{0,300}`), text is capped at 64 MB |

### C. MLScan ceasing to be a source of truth

| # | Scenario | Mechanics | Residual risk |
|---|----------|-----------|---------------|
| C1 | **Sandbox result forgery** | the service parses the **last** `MLSCAN_RESULT_JSON:` line from container stdout; there is **no nonce**, the result is unsigned and not cross-checked against the process outcome -> a payload prints a "clean" JSON (e.g. a forked process after the harness exits) | **critical**: false `Safe` / hidden findings |
| C2 | **Silent coverage degradation** | the payload "mutes" dynamics (kills the process, floods stdout, loops forever) | partially closed: `Inconclusive` + incomplete-scan banner; but there are no metrics/alerts for the `Inconclusive` share |
| C3 | **Policy/code substitution** | `mlscan-policy`, `mlscan-harness`, `mlscan-poc-lib`, `mlscan-formats`, `mlscan-i18n` are plain ConfigMaps without signature/integrity checks: an edit substitutes the decision rules and analysis logic | high (given access to the namespace) |
| C4 | **Evidence substitution** | evidence is append-only (file + PG triggers) but the **chain is unsigned**; with access to the PVC/DB it can be rebuilt entirely, and `attest.sh` (HMAC) runs manually | medium |
| C5 | **Static service-to-service key** | `analytics -> testing` uses a shared `INTERNAL_KEY` (role `service`); keys live in a Secret with **no expiry/rotation** and there is no mTLS: a leak allows serving false data or impersonating a service | high |
| C6 | **Registry/gate poisoning** | the integrations registry (`sha256 -> entry`) is filled during scanning; S3 is never overwritten (dedup by `sha256`) | low: the key is content, not a name |
| C7 | **Verdict race** | one `scan_id` per artefact; re-uploading the same sha reuses the object but creates a new scan | low |
| C8 | **UI data substitution** | XSS through artefact fields (name, findings, errors) | closed: fields are escaped (`_esc`), the cookie is `HttpOnly`+`SameSite=Lax` |

### D. Availability and operations

| # | Scenario | Mechanics | Residual risk |
|---|----------|-----------|---------------|
| D1 | **API/UI DoS** | no rate limits: uploads/requests to `/scans`, `/api/overview` (the dashboard polls every 5 s) | medium |
| D2 | **DB dependency** | `analytics`/`testing` write to PG synchronously; if PG is unavailable they degrade (files remain) | low: a file fallback exists |
| D3 | **Timeouts instead of refusals** | network attempts from the sandbox hang until timeout (DROP). Not an attack, but it slows scans (see P0-4) | low |

---

## 3. What is already done well (keep it)

* **Isolation**: one Kata microVM per artefact, `--network none` equivalent (default-deny + sinkhole/DNS),
  read-only rootfs, drop ALL, seccomp, limits, honeypot files, sinkhole addresses, environment destroyed.
* **The artefact never enters the trusted zone**: the sandbox downloads it from the service using a
  one-time token bound to `scan_id`; sandbox networking is not widened.
* **Honest verdicts**: incomplete coverage -> `Inconclusive` plus the list of unchecked items (in the
  service, in analytics and in the UI/reports); historical records are recalculated.
* **Data integrity**: evidence is append-only (file + DB triggers), hash-chained, artefacts are
  deduplicated by `sha256` and never overwritten.
* **Input validation**: `scan_id` is `[0-9a-f]{6,64}` only; `name` is `basename`d on upload and serving.
* **AuthN/sessions**: API keys and DB users (PBKDF2, 200k), sessions are HMAC-signed, 12 h, `HttpOnly`,
  `SameSite=Lax`, `Max-Age`; roles `admin`/`ci-reader`/`service`; audit in `audit_log`.
* **UI**: all fields escaped; the global language is configurable in the DB; no HTML from artefacts.
* **Operations**: metrics, quality (TPR/FPR), retention/TTL, quarantine, backup+restore, PDBs.

---

## 4. Remediation plan

### P0 - immediately (close direct untrustworthiness and the launchpad)

| ID | Task | Implementation | Acceptance |
|----|------|----------------|-----------|
| P0-1 | **Result nonce + cross-check** | `poc/mlscan_poc.py` (the harness prints `MLSCAN_RESULT_JSON:<nonce>:{...}`), `deploy/stage2/service/mlscan_testing.py` (generate a per-scan nonce, pass it to the Job via env, accept **only** its own line, cross-check `MLSCAN_SUMMARY:<nonce>` and the Job exit code/state) | a payload printing a fake `MLSCAN_RESULT_JSON` without the nonce **cannot** influence the verdict; a spoofer sample is added to `tests/vulnerabilities` |
| P0-2 | **Digest instead of a tag for the sandbox image** | `SANDBOX_IMAGE` accepts `image@sha256:...`; `deploy/stage2/30-service.yaml` + `install.sh` write the digest after the build; the Job uses the digest | retagging the registry image does not change executed code; verify checks the digest |
| P0-3 | **Decompression caps in the trusted zone** | `poc/formats.py`: read archive members only with a **decompressed** size cap (e.g. 32 MB) and a total-volume cap; compute the compression ratio before reading; cap the member count | a zip bomb (`FMT-04`) does not grow service RSS; a script test with a 1 KB->1 GB bomb |
| P0-4 | **Instant network refusal from the sandbox** | Calico `GlobalNetworkPolicy` for `mlscan-sandbox`: `Allow` (DNS resolver, sinkhole, testing:8090) then `Reject` instead of the implicit DROP; measure refusal time | a network call from the payload fails with `ConnectionRefused` < 1 s (not a timeout); a network-payload scan gets faster |
| P0-5 | **Limits and quotas for namespace/client** | `ResourceQuota`+`LimitRange` for `mlscan-sandbox`/`mlscan-data`; a cap on concurrent Jobs; a simple rate limit on `/scans/upload` per key/IP | an upload storm cannot take the node down; on excess -> `429`/`Inconclusive` without failure |
| P0-6 | **Configuration substitution protection** | RBAC: only the `admin` role may write service ConfigMaps; on start the services compare checksums of their ConfigMaps (`mlscan-poc-lib`, `mlscan-formats`, `mlscan-harness`, `mlscan-policy`) with expected values from a signed annotation/Secret | changing a ConfigMap without updating the reference blocks startup or raises a critical alert |

### P1 - next sprint (reduce the attack surface and raise trust)

| ID | Task | Implementation | Acceptance |
|----|------|----------------|-----------|
| P1-1 | **Narrow platform namespace egress** | `deploy/ingress/30-*.yaml`: instead of the whole cluster CIDR, allow only `mlscan-data`, the DNS resolver and the K8s API address; everything else -> `Reject` | from testing/analytics, foreign services and arbitrary 443/8080 in the cluster are unreachable |
| P1-2 | **Sandbox DNS policy** | allow DNS only to **our** resolver (or a NodeLocalDNS stub) that returns `NXDOMAIN` for external names; or static records for testing/sinkhole | the payload cannot resolve external domains -> no DNS tunnelling |
| P1-3 | **Restrict the testing service account** | Kyverno/ValidatingAdmissionPolicy: Jobs in `mlscan-sandbox` only with our image digest, a mandatory securityContext, and no hostPath/hostNetwork/privileged | any other Job in the sandbox namespace is rejected by admission |
| P1-4 | **Key lifetime and rotation** | `authz`: `expires_at` for API keys (the `api_keys` table), rotation procedure for `INTERNAL_KEY`/`SESSION_SECRET`; separate keys for analytics<->testing and ops<->analytics | an expired key -> 401; rotation without downtime; rotation events are audited |
| P1-5 | **Evidence and policy signing** | HMAC-chain evidence with the existing `attest.sh` (key outside the DB/PVC), run automatically by cron and on `/retest`; sign `policy.json` and verify it on load | editing an evidence row or the policy without the key breaks verification; the UI shows attestation status |
| P1-6 | **Integrity metrics and alerts** | `ops`: share of `Inconclusive`, share of incomplete dynamics, parse errors, summary/result mismatches, sandbox network refusals -> `/metrics` + `/alerts` | a drop in full coverage or a rise in forgeries/errors raises an alert |
| P1-7 | **Findings and JSON size caps** | cap the number of findings (e.g. 500, recording "truncated") and the evidence record size; report truncation explicitly | a finding explosion cannot bloat the DB/UI or silently change the verdict |
| P1-8 | **Audit of actions on our objects** | enable K8s audit (or log ConfigMap/Secret changes by our services) and export policy/harness changes to the SIEM | every change of analysis rules or code is visible in the SIEM |

### P2 - planned (long-term resilience and trust)

| ID | Task | Comment |
|----|------|---------|
| P2-1 | **Parser fuzzing** (zip/tar/XML/YAML/ONNX/GGUF/HDF5/safetensors) in CI + a hostile corpus per fix | turns "parsers were never fuzzed" into a verifiable property |
| P2-2 | **Sandbox image signing and SBOM** (cosign/syft) with admission verification | continues P0-2 into the supply chain; pinned pip dependency hashes |
| P2-3 | **mTLS/OIDC** between services and for operators (out of scope in doc 13; now a separate track) | removes reliance on the static `INTERNAL_KEY` |
| P2-4 | **WORM/external copy of evidence** (S3 object-lock, daily export + offline verification) | protects against chain rebuilding with PVC/DB access |
| P2-5 | **Per-user/team data isolation** (if multi-tenancy appears) | single-tenant today; split scan visibility as it grows |
| P2-6 | **Regular red-teaming** (extend `stage5/40-redteam-job.yaml`: result forgery, DNS tunnelling, overload) | turns the scenarios from §2 into automated tests |
| P2-7 | **Ingress-side rate limiting** (Istio rate limit/local ratelimit) | protects the UI/API from external flooding |

### Order and effect

1. **P0-1, P0-2, P0-6** - close direct verdict/logic substitution (the main trust risk).
2. **P0-3, P0-4, P0-5** - remove trusted-zone DoS and cluster overload (the risk to neighbouring projects).
3. **P1-1...P1-4** - shrink the attack surface and lateral movement.
4. **P1-5...P1-8, P2-\*** - provability, observability and the supply chain.

---

## 5. Appendix: how to verify after the changes

* **Result spoofer**: a sample that prints a fake `MLSCAN_RESULT_JSON:` - the verdict must not become
  "clean" (P0-1).
* **Zip bomb**: 1 KB -> 1 GB; service RSS stays under its limit and the status is `Inconclusive`/`FMT-04` (P0-3).
* **Network payload**: refusal time < 1 s, the event is recorded by sinkhole/Falco (P0-4).
* **Upload storm**: quota/`429`, the node and neighbouring projects do not degrade (P0-5).
* **ConfigMap edit**: the service does not start or raises an alert (P0-6).
* **Registry retag**: results do not change (P0-2).
* **Key expiry**: `401`; rotation without downtime (P1-4).
* **Attestation**: editing an evidence row breaks verification (P1-5).
