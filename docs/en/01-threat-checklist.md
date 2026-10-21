[Русский](../01-threat-checklist.md) | **English**

# Checklist of potential hazards of ML models in pickle format

> **Implemented checks** (`A-*`, `EXEC-*`, `INJ-*`, `AGT-*`, `BD-*`, `FMT-*`, `INT-*`, `STEG-*`,
> `SEC-*`, `D-*`) and how they map to risk classes are in
> [`07-implemented-architecture.md`](./07-implemented-architecture.md); the corpus of samples
> (with and without backdoors) is in [`../../tests/vulnerabilities/`](../../tests/vulnerabilities).

The document describes an exhaustive list of risks associated with the intake, storage,
loading and use of ML models supplied in pickle format (`.pkl`, `.pickle`,
`.joblib`, `.pt`, `.pth`, `.bin`, `.npy/.npz` with `allow_pickle=True`, `dill`,
`cloudpickle` and their derivatives).

The pickle format is capable of serializing **arbitrary Python objects and invoking
arbitrary code** during deserialization. Therefore, a model in pickle format is not
"data", but an **executable program** with a full set of associated risks.

Checklist categories:
- **A. Deserialization risks (execution-time)** — code executed during `load`/`unpickle`.
- **B. Wrapper formats and delivery vectors** — how a dangerous payload is disguised.
- **C. Model-level risks (model as an algorithm)** — maliciousness/defects of the model itself.
- **D. Integrity, provenance and supply chain**.
- **E. Information disclosure (information leaks)**.
- **F. Uncontrolled behaviour during load and inference**.
- **G. Risks of the execution environment and accompanying artifacts**.
- **H. Risks of the scanner infrastructure and the verification process**.
- **I. Legal, compliance and reputational risks**.

For each item the following are specified: identifier, description, mechanism/vector,
example, observable signs (observables), and severity level.

Severity scale: **C** — critical, **H** — high, **M** — medium, **L** — low.

---

## A. Deserialization risks (execution-time)

| ID | Risk | Mechanism | Observable signs | Severity |
|----|------|-----------|------------------|----------|
| A-01 | Arbitrary code execution (RCE) during `pickle.load` | Opcodes `REDUCE`, `GLOBAL`/`STACK_GLOBAL`, `BUILD` invoke arbitrary callables | Suspicious globals (`os.system`, `subprocess`, `eval`, `exec`, `builtins`, `getattr`) | C |
| A-02 | Execution via `__reduce__` | The object defines `__reduce__`/`__reduce_ex__` returning `(callable, args)` | Custom classes in pickle with a suspicious callable | C |
| A-03 | Execution via `__setstate__` / `BUILD` | `BUILD` triggers restoration of the object's state | Classes with `__setstate__` that reads files/network | H |
| A-04 | Shadowed `find_class` (interception of loading) | Overriding `pickle.Unpickler.find_class` expands the available names | Non-standard loaders, monkey-patching | H |
| A-05 | Dynamic compilation of code during load | `compile`, `types.FunctionType`, `marshal.loads`, `exec` | Presence of bytecode/marshal/`code` objects in the payload | C |
| A-06 | Obfuscation and packing of the payload | Base64/zlib/marshal inside pickle, multi-layered pickle | High entropy of strings, blob fields | H |
| A-07 | Nested/recursive pickle | pickle inside pickle, a hidden second payload | Nested `PROTO`, repeated `load` | H |
| A-08 | Use of obsolete/dangerous opcodes | `INST`, `OBJ`, `GLOBAL`, `EXT*` | Rare/obsolete opcodes | M |
| A-09 | `persistent_load` with side effects | Loading external data by key | `persistent_id`/`persistent_load` in a custom Unpickler | M |
| A-10 | Side-channel via pickle `PROTO`/`MEMO` | Extracting data via the order of opcodes | Anomalous stream structure | L |
| A-11 | RCE via `dill`/`cloudpickle` | They serialize functions/closures in their entirety | Complete `FunctionType` objects, source code | C |
| A-12 | RCE via `joblib` | joblib uses pickle + numpy | Malicious callables in the joblib container | C |
| A-13 | RCE via `torch.load` (legacy) | PyTorch uses pickle; `weights_only=False` | `_rebuild_*`, `torch.storage`, `torch.Size` tricks | C |
| A-14 | Bypass of `weights_only=True` | Historical vulnerabilities of allowlists | Known PyTorch CVEs (e.g. CVE-2025-32434) | C |
| A-15 | RCE via Keras Lambda layers | SavedModel/H5 with an arbitrary `Lambda` | `lambda` functions, Python code in the layer config | C |
| A-16 | RCE via numpy object-array | `.npy/.npz` with `allow_pickle=True` | Scalar object-arrays with a callable | C |
| A-17 | `trust_remote_code=True` (HF) | Loading and executing repository code | `auto_map`, custom `modeling_*.py` | C |
| A-18 | Code execution in custom ONNX ops | Custom operators / Python runtime | Non-standard operators, external libraries | H |

---

## B. Wrapper formats and delivery vectors

| ID | Risk | Mechanism | Observable signs | Severity |
|----|------|-----------|------------------|----------|
| B-01 | Disguise as a "safe" format | Dangerous pickle inside `.safetensors`-like packaging or a zip | Mismatch between the extension and the actual content | H |
| B-02 | Polyglot files | The file is valid both as an image/archive and as pickle | "Magic bytes" of several formats | H |
| B-03 | Zip-slip / path traversal in model archives | Unpacking `.zip`/`.tar` writes outside the directory | Names with `../`, absolute paths | H |
| B-04 | Zip-bomb / decompression bomb | Extreme unpacking during loading | Abnormally high compression ratio | M |
| B-05 | Loading external dependencies by URL | The model references an external resource | URL in the config, network calls during load | H |
| B-06 | Malicious `requirements`/`config.json` | The model pulls a malicious dependency | Install scripts, `--extra-index-url` | H |
| B-07 | Metadata spoofing | Fake card/model card, names | Mismatch between metadata and content | M |
| B-08 | Typosquatting of repositories/packages | Similar names of popular models | Edit distance to known names | M |
| B-09 | Malicious `__init__.py` in the model archive | Importing the package executes code | Python files within the artifact | H |
| B-10 | Malicious `setup.py`/`pyproject.toml` | Code during `pip install` of the artifact | Build hooks, arbitrary commands | H |

---

## C. Model-level risks (model as an algorithm)

| ID | Risk | Description | Observables | Severity |
|----|------|-------------|-------------|----------|
| C-01 | Backdoor / Trojan | Hidden behaviour triggered by a trigger | Sharp change of output on trigger inputs | C |
| C-02 | Trigger pattern (pixel/sticker/word) | A specific pattern activates the attack | Anomalies on synthetic triggers | H |
| C-03 | Data poisoning in weights | Poisoned weights affecting predictions | Anomalous distributions of weights/activations | H |
| C-04 | Model inversion | Reconstruction of training examples | Leakage via queries to the model | H |
| C-05 | Membership inference | Determining whether an example participated in training | Model confidence differs | M |
| C-06 | Leakage of PII / secrets (memorization) | The model reproduces training data | Verbatim fragments in outputs | H |
| C-07 | Leakage of IP / architecture | Reconstruction of hyperparameters/structure | Metadata, extraction methods | M |
| C-08 | Adversarial evasion | Subtle inputs change the prediction | Successful adversarial examples | M |
| C-09 | Steganography in weights | Hidden channel in tensors | Anomalous entropy/least significant bits | M |
| C-10 | Model skimming / extraction | Theft of the model via the API | High-volume identical queries | M |
| C-11 | Instability (NaN/Inf, overflow) | Numerical anomalies break the pipeline | NaN/Inf in outputs, crashes | M |
| C-12 | Excessive computational complexity | DoS via load during inference | High latency/CPU/GPU | M |
| C-13 | Adversarial evasion of detectors | The model deliberately bypasses filters | Bypassing safety-guardrails | M |
| C-14 | Bias / fairness defects | Discriminatory behaviour | Differences in metrics across subgroups | L |
| C-15 | Spurious correlation | False correlations from training data | Low robustness out of distribution | L |
| C-16 | Hidden functionality (dual-use) | Undeclared capabilities | Deviation from the declared purpose | H |
| C-17 | Incorrect class distribution / calibration | Incorrect probabilities | Poor calibration, class skew | L |
| C-18 | Model as "bait" (watering hole) | Distribution of a popular model with a backdoor | Anomalies of loading/behaviour | H |

---

## D. Integrity, provenance and supply chain

| ID | Risk | Description | Observables | Severity |
|----|------|-------------|-------------|----------|
| D-01 | Weight substitution (tampering) | Weights changed after signing | Hash/signature mismatch | C |
| D-02 | Absence of a signature | No provenance/attestation | No sigstore/SBOM | H |
| D-03 | Compromise of the owner's account | A malicious version under a legitimate name | Sudden changes in the repository | H |
| D-04 | Dependency confusion | An internal package is substituted by a public one | Mismatch of the dependency source | H |
| D-05 | Supply-chain in a base library | Vulnerability/backdoor in torch/numpy, etc. | Low-least known CVEs of the dependency | H |
| D-06 | Absence of versioning/immutability | The model changes without a version change | Unstable hash of the artifact | M |
| D-07 | Absence of SBOM | The composition of dependencies is unknown | No manifest | M |
| D-08 | License violation | Prohibited use of data/code | Incompatible licenses | M |
| D-09 | Removal of watermark/marks | Concealment of provenance | Absence of expected marks | L |

---

## E. Information disclosure (information leaks)

| ID | Risk | Mechanism | Observables | Severity |
|----|------|-----------|-------------|----------|
| E-01 | Theft of environment variables | The payload reads `os.environ` during load | Accesses to env | H |
| E-02 | Theft of credentials | Reading `~/.aws`, `~/.ssh`, `.netrc`, kubeconfig | Access to sensitive paths | C |
| E-03 | Exfiltration of files | Sending content to an external host | Outgoing connections during load | C |
| E-04 | Leakage of internal paths/host names | Hardcoding of internal infrastructure | Internal domains/IPs | L |
| E-05 | Capture of cloud metadata | Request to `169.254.169.254` | IMDS access | C |
| E-06 | Theft of CI/CD tokens | Reading runner tokens | Access to CI env/secrets | H |
| E-07 | Leakage of training data (PII) | The model reproduces data | Extraction via queries | H |
| E-08 | Leakage of the model's source code | Reconstruction of code/structure | Extraction from the artifact | M |
| E-09 | Capture of crypto material | Access to keys, wallets | Access to `~/.config`, keystores | C |

---

## F. Uncontrolled behaviour during load and inference

| ID | Risk | Description | Observables | Severity |
|----|------|-------------|-------------|----------|
| F-01 | Network access during load | reverse shell, C2 beacon, DNS/HTTPS callback | Outgoing traffic without a reason | C |
| F-02 | Writing to the file system | Modification of files, backdoor scripts | Modified/new files | H |
| F-03 | Persistence mechanisms | cron, systemd, `.bashrc`, autostart | New tasks/autorun | C |
| F-04 | Fork bomb / DoS | Multiplication of processes | Explosion of the number of PIDs, system failure | H |
| F-05 | Resource exhaustion | Memory/CPU/GPU/disk | OOM, 100% CPU, disk filling | H |
| F-06 | Infinite loops/hangs | Non-terminating load/inference | Timeout, absence of progress | M |
| F-07 | Self-modification of weights | The model modifies itself | Writing to the artifact during operation | M |
| F-08 | Sandbox escape | Exploitation of the kernel/container | Container-escape indicators | C |
| F-09 | Crypto-mining | Use of resources for mining | High load, accesses to pools | H |
| F-10 | Ransomware-like encryption | Encryption of environment files | Mass writing/encryption | C |
| F-11 | Attacks on the scanning system | Attack on the scanner itself/its dependencies | Impact on other jobs | H |
| F-12 | Cross-contamination of tasks | Leakage/corruption of data between scans | Shared volumes/state | H |
| F-13 | Logging/theft of results | Reading the data of other models | Access to shared directories | M |
| F-14 | Time/cache side channels | Extraction of secrets via timing | Microarchitectural anomalies | L |

---

## G. Risks of the execution environment and accompanying artifacts

| ID | Risk | Description | Observables | Severity |
|----|------|-------------|-------------|----------|
| G-01 | Unsafe host mounts | The model sees host paths | Recommended volumes/sockets | H |
| G-02 | Access to the Docker socket | Escape and full control | `/var/run/docker.sock` | C |
| G-03 | Unsafe default secrets | Tokens in the image/environment | Secrets in env | H |
| G-04 | Excessive capabilities | `CAP_SYS_ADMIN`, `--privileged` | Container flags | C |
| G-05 | Shared kernel/namespace | Escape via kernel exploits | Shared kernel | H |
| G-06 | Outdated kernel/engine | Known exploits | Runtime versions | H |
| G-07 | Unsafe scanner dependencies | Compromise of the toolchain | CVEs in dependencies | H |
| G-08 | Poor artifact control | Leakage/substitution of stored samples | Weak access to storage | M |

---

## H. Risks of the scanner infrastructure and the verification process

| ID | Risk | Description | Observables | Severity |
|----|------|-------------|-------------|----------|
| H-01 | False negatives (FN) | A dangerous model is deemed safe | Miss with an incomplete set of tests | C |
| H-02 | False positives (FP) | A safe model is rejected | Excessive alerts | M |
| H-03 | Incompleteness of coverage | Risk classes not tested | No tests for a category | H |
| H-04 | Determinism/reproducibility | Different results on repeats | Unstable verdicts | M |
| H-05 | Malicious "wiping" of traces | The payload detects the sandbox and "stays silent" | Conditional activation | H |
| H-06 | Compromise of the control plane | The attacker controls the verdict | Access to the DB/API | C |
| H-07 | Leakage via verification channels | Verification data leaks outside | Leakage of reports/logs | H |
| H-08 | Insufficient audit | It is impossible to reconstruct the course of verification | No immutable logs | M |
| H-09 | Incorrect attribution of the version | The verdict is attributed to the wrong artifact | Confusion of hash/versions | H |
| H-10 | Absence of test isolation | Contamination between checks | Shared state | H |

---

## I. Legal, compliance and reputational risks

| ID | Risk | Description | Severity |
|----|------|-------------|----------|
| I-01 | Privacy violation (GDPR/152-FZ) | Processing of PII without grounds | H |
| I-02 | Liability for an incident | Damage from an allowed dangerous model | H |
| I-03 | License incompatibility | Use outside the terms of the license | M |
| I-04 | Violation of export control | Dual use | M |
| I-05 | Reputational damage | A public incident with the model | H |
| I-06 | Absence of regulatory compliance | No AI Act / internal policies | M |

---

## Mapping to external frameworks

- **OWASP ML Top 10 (2023):** ML01 Input Manipulation, ML02 Data Poisoning, ML03 Model Inversion,
  ML04 Membership Inference, ML05 Model Theft, ML06 AI Supply Chain Attacks, ML07 Transfer Learning,
  ML08 Model Skewing, ML09 Output Integrity, ML10 Model Poisoning.
- **MITRE ATLAS:** Initial Access (ML Supply Chain Compromise, ML Artifact), Execution (User Execution),
  Persistence, Discovery, Collection, Exfiltration, Impact; techniques "Backdoor ML Model", "Poison Training Data".
- **CWE:** CWE-502 (Deserialization of Untrusted Data), CWE-94 (Code Injection), CWE-78 (OS Command Injection),
  CWE-200 (Information Exposure), CWE-400 (Uncontrolled Resource Consumption), CWE-22 (Path Traversal),
  CWE-770 (Allocation without Limits), CWE-284 (Improper Access Control).
- **MITRE ATT&CK (for the executable payload):** T1059 (Command and Scripting Interpreter),
  T1071 (Application Layer Protocol), T1543 (Create/Modify System Process), T1547 (Boot/Logon Autostart),
  T1041 (Exfiltration Over C2), T1496 (Resource Hijacking), T1486 (Data Encrypted for Impact).

## Prioritization (top risks for the first implementation)

1. **A-01/A-02/A-13/A-14/A-15/A-16/A-17** — RCE during deserialization.
2. **F-01/F-03/F-09/F-10** — network impact, persistence, mining, encryption.
3. **E-01/E-02/E-03/E-05** — theft of secrets and exfiltration.
4. **B-01/B-06/B-09/B-10** — disguise and malicious dependencies.
5. **C-01/C-03/C-06/C-16** — backdoor, poisoning, data leakage, hidden functionality.
6. **D-01/D-02/D-03/D-04** — integrity and provenance.

## Key conclusion for the architecture

The danger of a pickle model goes far beyond "executing malicious code during loading".
Full coverage requires three independent verification contours:

1. **Static** — analysis of the artifact without execution (opcodes, AST, allowlist, metadata, integrity).
2. **Dynamic** — execution in a hermetic sandbox with full observation (syscalls, network, files, resources).
3. **Behavioural** — testing an already running model for backdoors, leaks and reliability defects.

These three contours map onto three architectural components (Sandbox, Testing Service,
Analytical Engine) — see `./05-architecture.md` and `../../Concept.md`.
