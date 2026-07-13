<div align="center">

# qryx — Cryptography Security Graph

**Discover what's encrypted, where, and with which algorithm — then assess quantum risk and migrate.**

[![CI](https://github.com/TAIPANBOX/qryx/actions/workflows/ci.yml/badge.svg)](https://github.com/TAIPANBOX/qryx/actions/workflows/ci.yml)
![Go](https://img.shields.io/badge/go-1.26-00ADD8.svg)
![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)
![Status](https://img.shields.io/badge/phase-4%20(governance)-success.svg)

<img src="docs/architecture.png" alt="qryx architecture: sources flow through the scan engine into a cryptographic asset graph and out to CBOM, reports and drift gates" width="960">

</div>

qryx builds an organization-wide inventory of cryptography across code,
binaries, container images, live TLS endpoints, certificates, dependencies and
cloud KMS — normalizes it into a single **cryptographic asset graph**, scores
each asset for post-quantum and hygiene risk, and emits a standard **CBOM**
(CycloneDX). Open-core, dev-first, built for mid-market. See
[`qryx-plan.md`](./qryx-plan.md) for the full design and roadmap.

---

## Where this fits in the stack

Qryx is the crypto plane of the TAIPANBOX agent-governance stack: it scans Agent Passports, agent-event hash-chains, and real crypto artifacts for post-quantum and hygiene risk.

```mermaid
flowchart TB
  Agent["AI agent (any framework)"] -->|"LLM call (base-URL swap)"| TF["TokenFuse proxy: spend + enforcement"]
  TF -->|"POST /v1/decide (PEP)"| WX["Wardryx: policy PDP"]
  WX -.->|"allow / deny / hold"| TF
  TF -->|"cheapest model, budget OK"| LLM[("LLM provider")]
  TF -->|"CallRecords"| CL["TokenFuse Cloud: control plane, incidents, replay, evidence, kill-switch"]
  TF ==>|"agent-event NDJSON"| BUS{{"agent-event bus + Agent Passport"}}
  WX ==> BUS
  ENG["Engram: memory"] -->|"reflect via base_url"| TF
  ENG ==> BUS
  BUS ==> IDX["Idryx: identity graph, detectors, Agent-BOM"]
  BUS ==> QX["Qryx: crypto / PQC, passport + hash-chain scan"]
  BUS ==> VX["Verdryx: quality / drift"]
  VX ==>|"quality events"| BUS
  TF -->|"outcome-tagged traces"| VX
  MX["Mockryx: pre-prod safety rehearsal"] -->|"hostile scenarios"| TF
  MX ==>|"sim events"| BUS
  TFP["terraform-provider-taipan"] -->|"budgets + passports as code"| CL
  ASG[["agent-stack-go: shared Go contract"]] -.->|imported by| IDX
  ASG -.->|imported by| WX
  ASG -.->|imported by| MX
  ASG -.->|imported by| TFP
  SPEC[["agent-passport: the spec"]] -.->|governs| BUS
```

- **Consumes**: Agent Passports and agent-event NDJSON (`qryx agents` checks attestation and `prev_hash` chains), plus real crypto artifacts (code, binaries, TLS, cloud KMS).
- **Produces**: NCSC/CNSA/CycloneDX crypto posture reports.
- **Talks to**: **agent-passport** (the passport and event schema it scans), fed by the same agent-event bus that **TokenFuse**, **Wardryx**, and **Engram** write to.

The full stack is TokenFuse (spend), Wardryx (policy), Engram (memory), Idryx (access), Qryx (crypto), Verdryx (quality), Mockryx (pre-prod), on the shared Agent Passport + agent-event contract (agent-stack-go / agent-passport), configured via terraform-provider-taipan.

## Live infrastructure validation

Before any public launch, Qryx was run against 25,586 real Linux ELF binaries, a real container image,
and a live TLS endpoint: no crashes, and a live scan of `api.anthropic.com` correctly flagged its
certificate as quantum-vulnerable under the NCSC 2035 timeline.

![Qryx crypto inventory: 4 real targets scanned, 20 assets in /usr/bin, live TLS handshake against api.anthropic.com flagged](assets/08-qryx.png)

Full write-up and the two real bugs live testing found (and fixed): [`VALIDATION.md`](VALIDATION.md).

---

## Why now

<div align="center">
<img src="docs/why-now.png" alt="Timeline: 2024 NIST PQC standards, 2027 CNSA 2.0 new systems, 2030 legacy migration, 2035 full migration" width="900">
</div>

NIST standardized post-quantum algorithms in 2024 (FIPS 203/204/205) and
**CNSA 2.0** fixes the deadlines: new systems on PQC by 2027, legacy migration
by 2030, complete by 2035. **"Harvest now, decrypt later"** means data encrypted
with quantum-vulnerable crypto today can be captured now and decrypted once a
cryptographically relevant quantum computer exists — so the exposure is already
real. Migration starts with **discovery**, and organizations consistently find
**3–5× more cryptographic assets than expected**. You can't migrate what you
can't see.

---

## How it works

qryx is a pipeline: **sources → scan engine → asset graph → outputs** (the
diagram at the top). Every connector emits findings in one model; they are
deduplicated into a graph of unique assets, each carrying every place it occurs.

| Stage | What it covers |
|---|---|
| **Sources** | source code (Go · Python · JS · TS), Terraform/HCL, binaries (ELF · PE · Mach-O), container images (`docker save` / OCI), live TLS endpoints, PEM/x509 certificates, dependency manifests, cloud KMS (AWS KMS + ACM · GCP KMS · Azure Key Vault), AI-agent infrastructure (Agent Passport identity docs + agent-event NDJSON streams) |
| **Scan engine** | AST + parser detectors (`goast`, `cryptocall`, `certfile`, `tlsconfig`, `hardcoded`, `deps`, `terraform`), the binary/image/TLS/cloud connectors, and the risk classifier |
| **Asset graph** | one node per logical asset **and risk class** (algorithm + key size + risk class), deduplicated across all sources, with every occurrence attached |
| **Outputs** | CycloneDX 1.6 CBOM · human · HTML · CNSA 2.0 audit · NCSC PQC readiness · migration plan · signed evidence attestation · governance dashboard · JSON/Postgres snapshots · CI drift, severity & policy gates |

---

## Risk model

<div align="center">
<img src="docs/risk.png" alt="Risk classes: quantum-vulnerable, weak, misconfig, expired, hardcoded, and post-quantum safe" width="900">
</div>

Every asset is scored against a post-quantum and hygiene model:

| Class | Examples | Why |
|---|---|---|
| `quantum-vulnerable` | RSA · ECC · DSA · DH | breakable by Shor's algorithm on a CRQC |
| `weak` | MD5 · SHA-1 · DES · RC4 · RSA&lt;2048 | broken or deprecated primitives |
| `misconfig` | TLS 1.0/1.1 · insecure cipher suites | unsafe protocol settings |
| `expired` | past-due certificates | validity window elapsed |
| `hardcoded` | private keys in source/config | secrets embedded in the tree |
| `safe` | ML-KEM · ML-DSA · SLH-DSA | post-quantum (FIPS 203/204/205) |

---

## Drift detection in CI

<div align="center">
<img src="docs/ci-drift.png" alt="Baseline snapshot, then a new scan diffs against it; CI passes on no new risk, blocks when a new high-risk asset appears" width="900">
</div>

Snapshot the asset graph, then fail the build when a **new** weak or
quantum-vulnerable asset is introduced — the "don't add new weak crypto" gate.

```bash
qryx scan --save base.json <path>                              # 1. baseline
qryx scan --baseline base.json --fail-on-new high <path>       # 2. diff → exit 2 on new high-risk
```

---

## Supply-chain hygiene

qryx is a security tool, so its own build is held to the standard it audits
others against. A dedicated `security` CI job (Go 1.26.5) runs `govulncheck`
against every dependency and `gosec` static analysis on every push to `main`;
both are clean. Every gosec finding was either fixed (scoped file reads via
`os.Root`, tightened file/dir permissions, explicit handling of best-effort
cleanup errors) or is a deliberate pattern annotated inline with a
`#nosec Gxxx -- reason` comment on the exact offending line — e.g. `qryx tls`'s
`InsecureSkipVerify` (it inspects TLS posture, it doesn't trust it) — never a
blanket CI exclude.

---

## Install

Prebuilt binaries (Linux, macOS, Windows) are published on the
[Releases page](https://github.com/TAIPANBOX/qryx/releases) for every `v*` tag,
with a `SHA256SUMS` file for verification:

```bash
tar -xzf qryx_v*_$(uname -s | tr A-Z a-z)_$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/').tar.gz
sha256sum -c SHA256SUMS --ignore-missing
./qryx version
```

Or build from source (Go 1.26+):

```bash
make build   # → ./bin/qryx
```

> Maintainers: a release is cut automatically by CI on `git tag vX.Y.Z && git push --tags`.

## Quick start

```bash
make build

qryx scan <path>                       # static scan of a code tree
qryx scan --format cbom <path>         # CycloneDX 1.6 CBOM (JSON)
qryx scan --format html <path> > report.html   # self-contained web report
qryx scan --format cnsa <path>               # CNSA 2.0 compliance audit (JSON)
qryx scan --format cnsa-html <path> > cnsa.html  # CNSA 2.0 audit (HTML)
qryx scan --format ncsc <path>               # NCSC PQC migration readiness, 2028/2031/2035 milestones (JSON)
qryx scan --format ncsc-html <path> > ncsc.html  # NCSC readiness (HTML)
qryx scan --format evidence <path> > evidence.json  # tamper-evident compliance attestation
qryx scan --format evidence --sign-key key.pem <path> > evidence.json  # ...signed (ed25519/ECDSA/ML-DSA)
qryx verify-evidence evidence.json     # verify a signed attestation
qryx scan --format dashboard <path> > dashboard.html # one-page governance dashboard
qryx scan --save-evidence trail.jsonl <path>   # append a dated compliance record
qryx trend trail.jsonl                 # show the compliance-score history
qryx trend --html trail.jsonl > trend.html     # ...as an SVG chart
qryx trend --fail-on-regression trail.jsonl    # exit 3 if the score dropped (CI)
qryx scan --format migration <path>          # risk-prioritized migration plan (JSON)
qryx scan --fail-on high <path>        # exit 2 if any finding >= high (for CI)
qryx scan --policy cnsa <path>         # enforce a crypto policy; exit 3 on violation
qryx scan --policy .qryx-policy.json <path>   # ...or a custom JSON policy
qryx scan --policy cnsa --baseline base.json --policy-new-only <path>  # fail only on NEW violations

qryx fix <path>                        # show safe code patches as a unified diff
qryx fix --write <path>                # apply them in place (e.g. raise RSA key size)
qryx fix --open-pr <path>              # apply, branch, commit and open a GitHub PR (git+gh)

qryx tls example.com:443               # probe a live endpoint's TLS posture
qryx bin /usr/bin/openssl              # crypto in a binary (ELF/PE/Mach-O)
docker save app:latest -o img.tar && qryx image img.tar   # scan a container image
qryx aws --region us-east-1            # inventory AWS KMS keys + ACM certs
qryx gcp --project my-project          # inventory GCP Cloud KMS key versions
qryx azure --vault-url https://myvault.vault.azure.net/  # inventory Azure Key Vault
qryx agents ./passports                # inventory AI-agent attestation crypto + event-stream integrity
qryx agents --events events.ndjson ./passports  # ...and append findings as agent-event NDJSON

qryx scan --save base.json <path>      # snapshot the asset graph
qryx scan --baseline base.json <path>  # report drift vs the baseline
```

> Flags must precede the positional path/targets (`qryx scan [flags] <path>`).
> `qryx tls` connects only to the exact `host:port` arguments you pass — no port
> ranges, no host discovery. Probe only endpoints you are authorized to test.

Run against the bundled fixtures with `make scan`.

---

## What works today

**Code scan** (`qryx scan`) — 7 detectors:

| Detector | Covers |
|---|---|
| `goast` | crypto usage in Go via AST import resolution (no regex false positives) |
| `cryptocall` | crypto API usage in Python / JS / TS source |
| `certfile` | PEM certificate parsing (algorithm, key size, expiry) |
| `tlsconfig` | legacy TLS/SSL in code and nginx/apache config |
| `hardcoded` | private keys embedded in source/config |
| `deps` | crypto libraries in dependency manifests |
| `terraform` | key material in HCL via the hashicorp/hcl parser (`tls_private_key`, `aws_kms_key`, `azurerm_key_vault_key`, `google_kms_crypto_key`) |

**TLS probing** (`qryx tls`) — negotiated TLS version, insecure cipher suites,
and the leaf certificate's public-key algorithm, size and expiry.

**Binary scanning** (`qryx bin`) — ELF/PE/Mach-O via `debug/elf|pe|macho`,
mapping needed crypto libraries and imported symbols to assets: both the
legacy flat OpenSSL API (`MD5_*`, `RSA_*`, …) and OpenSSL 3.x's `EVP_*`
interface (`EVP_aes_*`, `EVP_sha256`, `EVP_PKEY_CTX_set_rsa_*`, …), since
modern OpenSSL 3.x builds call crypto almost exclusively through `EVP_*`, so
both are resolved. Symbol/library based, not string scraping; low false
positives.

*Known blind spot: statically-linked crypto.* Detection is primarily via the
dynamic import table (`.dynsym` / needed libraries); a statically-linked
OpenSSL/BoringSSL/libsodium binary, a Rust binary using `ring`/`rustls`, or a
Go binary with its crypto compiled in has none of that, and used to scan as
"clear". For ELF, a non-stripped static binary now also falls back to the
full symbol table (`.symtab`), so its crypto symbols are still caught. A
**stripped** static binary has no `.symtab` either, and PE/Mach-O have no
equivalent fallback implemented yet: both stay invisible to this scanner
regardless of stripping. Treat a "clear" `qryx bin` result on a statically-
linked binary as limited assurance, not proof there is no crypto in it.

**Container images** (`qryx image`) — extracts a local image tarball
(`docker save` / OCI) with stdlib tar/gzip, hardened against path traversal and
tar bombs, then runs the code and binary scanners over the layers.

**AWS cloud** (`qryx aws --region <r>`) — KMS keys (by key spec) and ACM
certificates (algorithm + expiry) via the default credential chain. The SDK sits
behind an interface seam so the connector logic is unit-tested without an account.

**GCP cloud** (`qryx gcp --project <id>`) — Cloud KMS key versions mapped by
algorithm (RSA/EC/AES/HMAC, and PQC ML-DSA/ML-KEM/SLH-DSA as safe) via
Application Default Credentials, behind the same lister seam.

**Azure cloud** (`qryx azure --vault-url <url>`) — Key Vault keys mapped by JSON
Web Key type (EC/EC-HSM → ECDSA, RSA/RSA-HSM → RSA with size from modulus,
oct/oct-HSM → AES) via DefaultAzureCredential. Expired keys are flagged
separately.

**AI-agent infrastructure** (`qryx agents <path>`) — inventories the
agent-governance stack's own trust surface: Agent Passport `attestation.method`
(mTLS/SPIFFE → certificate-based, enclave key → hardware-backed and safe, OIDC
→ token-based, none → a `misconfig` finding) and agent-event NDJSON
`prev_hash` chains (every event carries a distinct sha256 prev_hash → a
sha256 hash asset; any event missing one, or the same value repeated across
events, → a `misconfig` finding). The chain check is structural: it confirms
every event is linked and no hash is suspiciously reused, but it does not
recompute each event's canonical hash to verify a prev_hash equals the actual
predecessor. Passport/event files are told apart by their `schema` field, not
extension; malformed files are counted and skipped, never fatal. Identity and
privilege stay Idryx's job — this connector stays strictly on the crypto axis.

**Agent-event export** (`--events <path>`, `internal/exporter`): appends
findings, drift, policy violations, and signed-evidence records as agent-event
NDJSON (`taipanbox.dev/agent-event/v0.1`, `source: "qryx"`, per agent-passport
SPEC.md §6.2's `crypto_finding`/`crypto_drift`/`policy_violation`/
`evidence_signed` types), the producer half of qryx's Passport-awareness (it
was already a consumer via `qryx agents` resolving `agent_id` as an evidence
subject). Opt-in, fail-open, and agent_id is never fabricated: only findings
carrying a real subject emit at all, which today means `qryx agents`'
passport findings specifically -- the vast majority of qryx's other sources
(code, binaries, TLS, cloud KMS) have no agent concept, so `--events` is a
no-op for them by design, not an oversight. `crypto_drift` and
`policy_violation` reuse the exact same `--baseline`/`--policy` results the
human report prints, filtered to the subset with a real agent_id;
`evidence_signed` fires once per distinct agent covered by a signed
`--format evidence` document, not once per finding.

**Asset graph** — findings from every source collapse into one node per logical
asset **and risk class**, deduplicated across files and sources: the same
algorithm and key size but two orthogonal risks (say, a certificate that is
both expired **and** quantum-vulnerable) become two nodes, not one, so neither
risk is silently dropped. The CBOM emits one CycloneDX component per node with
all its occurrences; the human report shows asset-level counts (one `RSA` row
with 112 occurrences, not 112 rows, though a physical asset carrying two risk
classes shows up as two rows, one per risk); `--format html` renders the same
graph as a static page.

**Persistence** — behind a `Store` interface with two backends: a JSON file (any
path) and **Postgres** (a `postgres://` URL), persisting the graph into
normalized `scans`/`assets`/`occurrences` tables.

```bash
qryx scan --save 'postgres://user:pass@host:5432/db' <path>
qryx scan --baseline 'postgres://user:pass@host:5432/db' --fail-on-new high <path>
```

**Compliance & governance reports** — five reports form a compliance pack for
regulated orgs, all computed from the same asset graph and the same risk
classification so they can never disagree with one another:

**CNSA 2.0 audit** (`--format cnsa`/`cnsa-html`) — classifies every asset
against the NSA's CNSA 2.0 suite: ML-KEM/ML-DSA/SLH-DSA and AES-256/SHA-384+
are compliant; RSA/ECDSA/ECC/DSA/DH are non-compliant with a 2030 migration
deadline; MD5/SHA-1/DES/3DES/RC4 and sub-floor keys are non-compliant
immediately; expired certificates, hardcoded keys and TLS misconfig are
flagged as issues. Reports compliant/non-compliant/issue counts, a percentage
score, and a per-asset remediation action, sorted by deadline urgency.
`--policy cnsa` enforces the same standard as a CI gate (see Policy
enforcement below); this report is the audit view, in JSON or HTML.

**NCSC PQC readiness** (`--format ncsc`/`ncsc-html`) — tracks the same graph
against the UK NCSC's three-milestone PQC migration timeline: complete
discovery by 2028, migrate the highest-priority systems by 2031, migrate
everything by 2035. Each milestone gets a deterministic
`on-track`/`at-risk`/`not-started` verdict — 2028 is at-risk if any
quantum-vulnerable asset has no recognized migration target; the 2031
"highest-priority" subset is quantum-vulnerable **and** either
externally-facing (seen via a live TLS probe or an AWS ACM certificate) or
long-lived data (an encryption/key-exchange primitive, i.e. exposed to
harvest-now-decrypt-later) — the exact predicate is embedded as a criteria
string in both outputs, so the report documents its own rules. The migrated
count is honestly reported as 0 within a single scan (qryx doesn't persist
remediation state across runs); track real progress with `--baseline` drift
or the evidence trail (`--save-evidence` / `qryx trend`) below.

**Migration plan** (`--format migration`) — scores each non-compliant asset's
*agility* (how hard it is to change: `high` for managed KMS keys you rotate via
API, `medium` for config/cert/dependency changes, `low` for code that needs a
redeploy) and emits a risk-prioritized plan. Each entry carries a recommended
PQC/strong target (RSA→ML-DSA/ML-KEM, ECDSA/DSA/Ed25519→ML-DSA, MD5/SHA-1→SHA-256,
etc.), a rationale and the occurrence locations. Quick wins — high-agility,
high/critical severity — are counted in the summary. Works on any source,
including cloud: a KMS RSA key reports `high` agility, the same algorithm in
source reports `low`.

**Remediation** (`qryx fix`) — turns findings into reviewable source patches,
but only for transforms that are *provably safe*. Today that is raising a
sub-floor RSA key size — in Go (`rsa.GenerateKey(rand, 1024)` → `3072`) and in
Terraform (`rsa_bits = 1024` → `3072`), configurable via `--min-rsa-bits`: a
single integer-literal change that stays valid and compiles. By default it
prints a unified diff; `--write` applies it in place. Algorithm swaps
(MD5→SHA-256) and hybrid schemes change semantics and break downstream
consumers, so they stay as migration *guidance* and are never auto-applied.
With `--open-pr` the fix is applied on a fresh branch and opened as a GitHub
pull request (via `git` + `gh`), with the rationale and diff in the PR body —
guarded by a clean-working-tree check so it never mixes in unrelated edits.

**Policy enforcement** (`--policy`) — gate CI on a declarative crypto policy.
Pass a builtin (`cnsa`) or a JSON file; qryx evaluates the deduped asset graph
and, on any violation, prints a report to stderr and exits **3** (distinct from
`--fail-on`'s severity gate, exit 2, so CI can tell them apart). The builtin
`cnsa` forbids weak algorithms (MD5, SHA-1, DES, 3DES, RC4, DSA), requires
RSA ≥ 3072, and rejects hardcoded keys / expired certs / TLS misconfig;
quantum-vulnerable assets are opt-in (`forbidQuantumVulnerable`) since their
CNSA deadline is 2030. A custom policy is plain JSON:

```json
{
  "name": "example-strict",
  "forbidAlgorithms": ["MD5", "SHA-1", "DES", "3DES", "RC4", "DSA"],
  "minRsaBits": 3072,
  "forbidQuantumVulnerable": false,
  "forbidHardcoded": true,
  "forbidExpired": true,
  "forbidMisconfig": true,
  "maxSeverity": "medium"
}
```

`--policy` writes only to stderr, so `--format cbom`/`html` output on stdout
stays valid. Add `--baseline <snapshot> --policy-new-only` to gate on *drift* —
only assets new since the baseline are evaluated, so a clean policy can be
adopted on a legacy codebase without blocking on pre-existing debt while still
failing any newly introduced weak crypto.

**Evidence export** (`--format evidence`) — a self-describing, tamper-evident
compliance attestation for audit/GRC: tool + version, UTC timestamp, scan root,
a CNSA 2.0 compliance summary (compliant / non-compliant / issues, score, and a
breakdown by severity), the per-asset records, and a `sha256:` content digest
over the document with the digest field blanked. A verifier recomputes the hash
the same way to confirm the artifact is unmodified — integrity without key
management. Reuses the same CNSA classification as `--format cnsa`, so the two
never disagree. Commit `evidence.json` as a CI artifact for a dated audit trail.

Pass `--sign-key <pkcs8.pem>` to add a detached signature over the digest
(ed25519, ECDSA P-256, or ML-DSA (FIPS 204) -- stdlib only, no cosign
dependency), embedding the public key so the artifact is self-verifying:

```bash
openssl genpkey -algorithm ed25519 -out key.pem
qryx scan --format evidence --sign-key key.pem ./src > evidence.json
qryx verify-evidence evidence.json   # VERIFIED (ed25519, key sha256:...) or exit 1

# post-quantum: ML-DSA-44/65/87, all three levels accepted -- seed-only
# encoding required (Go's x509 parser doesn't support OpenSSL's default
# seed+expanded PKCS#8 form)
openssl genpkey -algorithm ML-DSA-44 -provparam ml-dsa.output_formats=seed-only -out mldsa-key.pem
qryx scan --format evidence --sign-key mldsa-key.pem ./src > evidence.json
qryx verify-evidence evidence.json   # VERIFIED (ml-dsa-44, key sha256:...) or exit 1
```

`verify-evidence` recomputes the digest, confirms the document is unmodified,
and checks the signature against the embedded key, printing its fingerprint to
compare against your trusted signer. ed25519 and ECDSA P-256 remain
classically strong but quantum-vulnerable; ML-DSA is the quantum-resistant
option, requiring Go 1.27+ (`crypto/mldsa`).

**Governance dashboard** (`--format dashboard`) — one self-contained HTML page
for a security lead: the CNSA compliance score, the risk profile by severity,
the evidence integrity digest, and the **top remediation priorities** (the
compliance × agility ranking — which assets to fix first and what to migrate
them to). It aggregates the CNSA, migration and evidence views that are
otherwise separate; numbers come from the same computations, so it can't
disagree with them.

**Evidence trail** (`--save-evidence` + `qryx trend`) — append one compact,
digest-stamped record per run to a JSON-Lines trail (date, score, non-compliant
count, integrity digest). `qryx trend <trail>` renders the history and the
latest score delta (improved / regressed / unchanged), so a team can prove
posture over time and catch regressions. `--html` renders the history as a
self-contained SVG line chart; `--fail-on-regression` exits 3 when the latest
score is below the previous run, turning the trail into a CI monitor. Records
share the same numbers and digest as `--format evidence`. The trail works with a
file path or a `postgres://` URL (same backends as `--save`/`--baseline`):

```bash
qryx scan --save-evidence 'postgres://user:pass@host:5432/db' <path>
qryx trend 'postgres://user:pass@host:5432/db'
```

---

## Status

**Phases 0-4 complete, including post-quantum evidence signing:**

- [x] static code scan · TLS probing · binary scanning (ELF/PE/Mach-O) · container images
- [x] cross-source CBOM asset graph · JSON/Postgres persistence · drift detection · CI gate
- [x] human / CBOM (CycloneDX 1.6) / HTML reports -- all CI-gated
- [x] Phase 2 cloud KMS -- AWS, GCP and Azure done; owner-mapping; CNSA 2.0 audit report
- [x] Phase 3 -- crypto-agility scoring (`--format migration`), safe code remediation (`qryx fix` / `--open-pr`), Terraform detector + rule
- [x] Phase 4 -- policy engine (`--policy`, exit 3), drift-gated (`--policy-new-only`), evidence export (`--format evidence`), governance dashboard (`--format dashboard`), evidence trail + trend (`--save-evidence` / `qryx trend`)
- [x] Phase 4 -- evidence signing + verification (`--sign-key` / `qryx verify-evidence`, ed25519, ECDSA P-256, or ML-DSA (FIPS 204, all three security levels))
- [x] Phase 4 -- trend monitoring: HTML chart (`trend --html`) + regression CI gate (`trend --fail-on-regression`)
- [x] Terraform -- HCL-accurate detection via hashicorp/hcl (heredoc/interpolation-safe) + `google_kms_crypto_key`
- [x] Phase 4 -- NCSC PQC readiness report (`--format ncsc`/`ncsc-html`): 2028/2031/2035
  milestones, deterministic on-track/at-risk/not-started verdicts, self-documenting
  2031 highest-priority criteria; Ed25519 now maps to ML-DSA (FIPS 204) in the
  agility/migration plan
- [x] Phase 4 -- `qryx agents`: AI-agent infrastructure connector inventorying the
  agent-governance stack's own trust surface (Agent Passport attestation crypto,
  agent-event NDJSON hash-chain integrity) into the same asset graph
- [x] ML-DSA signing (`internal/attest`): stdlib `crypto/mldsa` (Go 1.27,
  `toolchain go1.27rc2` in `go.mod` until GA), additive 3rd case in the
  existing ed25519/ECDSA switch; live-verified against real openssl-generated
  keys end to end, all three security levels (`ML-DSA-44/65/87`)
- [x] Agent-event export (`--events`, `internal/exporter`): the emitter half
  of qryx's agent-passport SPEC.md §9 adoption row (`qryx agents` already
  shipped `agent_id`-as-evidence-subject as a consumer); `crypto_finding`,
  `crypto_drift`, `policy_violation`, `evidence_signed` per SPEC.md §6.2,
  agent_id never fabricated; live-verified end to end for all four types

Roadmap and rationale: [`qryx-plan.md`](./qryx-plan.md).

## License

[Apache-2.0](./LICENSE).
