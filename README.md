<div align="center">

# qryx — Cryptography Security Graph

**Discover what's encrypted, where, and with which algorithm — then assess quantum risk and migrate.**

[![CI](https://github.com/TAIPANBOX/qryx/actions/workflows/ci.yml/badge.svg)](https://github.com/TAIPANBOX/qryx/actions/workflows/ci.yml)
![Go](https://img.shields.io/badge/go-1.26-00ADD8.svg)
![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)
![Status](https://img.shields.io/badge/phase-2%20(cloud)-success.svg)

<img src="docs/architecture.png" alt="qryx architecture: sources flow through the scan engine into a cryptographic asset graph and out to CBOM, reports and drift gates" width="960">

</div>

qryx builds an organization-wide inventory of cryptography across code,
binaries, container images, live TLS endpoints, certificates, dependencies and
cloud KMS — normalizes it into a single **cryptographic asset graph**, scores
each asset for post-quantum and hygiene risk, and emits a standard **CBOM**
(CycloneDX). Open-core, dev-first, built for mid-market. See
[`qryx-plan.md`](./qryx-plan.md) for the full design and roadmap.

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
| **Sources** | source code (Go · Python · JS · TS), binaries (ELF · PE · Mach-O), container images (`docker save` / OCI), live TLS endpoints, PEM/x509 certificates, dependency manifests, cloud KMS (AWS KMS + ACM) |
| **Scan engine** | AST + parser detectors (`goast`, `cryptocall`, `certfile`, `tlsconfig`, `hardcoded`, `deps`), the binary/image/TLS/cloud connectors, and the risk classifier |
| **Asset graph** | one node per logical asset (algorithm + key size), deduplicated across all sources, with every occurrence attached |
| **Outputs** | CycloneDX 1.6 CBOM · human report · self-contained HTML · JSON/Postgres snapshots · CI drift gate |

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

## Quick start

```bash
make build

qryx scan <path>                       # static scan of a code tree
qryx scan --format cbom <path>         # CycloneDX 1.6 CBOM (JSON)
qryx scan --format html <path> > report.html   # self-contained web report
qryx scan --fail-on high <path>        # exit 2 if any finding >= high (for CI)

qryx tls example.com:443               # probe a live endpoint's TLS posture
qryx bin /usr/bin/openssl              # crypto in a binary (ELF/PE/Mach-O)
docker save app:latest -o img.tar && qryx image img.tar   # scan a container image
qryx aws --region us-east-1            # inventory AWS KMS keys + ACM certs
qryx gcp --project my-project          # inventory GCP Cloud KMS key versions
qryx azure --vault-url https://myvault.vault.azure.net/  # inventory Azure Key Vault

qryx scan --save base.json <path>      # snapshot the asset graph
qryx scan --baseline base.json <path>  # report drift vs the baseline
```

> Flags must precede the positional path/targets (`qryx scan [flags] <path>`).
> `qryx tls` connects only to the exact `host:port` arguments you pass — no port
> ranges, no host discovery. Probe only endpoints you are authorized to test.

Run against the bundled fixtures with `make scan`.

---

## What works today

**Code scan** (`qryx scan`) — 6 detectors:

| Detector | Covers |
|---|---|
| `goast` | crypto usage in Go via AST import resolution (no regex false positives) |
| `cryptocall` | crypto API usage in Python / JS / TS source |
| `certfile` | PEM certificate parsing (algorithm, key size, expiry) |
| `tlsconfig` | legacy TLS/SSL in code and nginx/apache config |
| `hardcoded` | private keys embedded in source/config |
| `deps` | crypto libraries in dependency manifests |

**TLS probing** (`qryx tls`) — negotiated TLS version, insecure cipher suites,
and the leaf certificate's public-key algorithm, size and expiry.

**Binary scanning** (`qryx bin`) — ELF/PE/Mach-O via `debug/elf|pe|macho`,
mapping needed crypto libraries and imported symbols (`MD5_*`, `RSA_*`, …) to
assets. Symbol/library based, not string scraping; low false positives.

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

**Asset graph** — findings from every source collapse into one node per logical
asset, deduplicated across files and sources. The CBOM emits one CycloneDX
component per asset with all occurrences; the human report shows asset-level
counts (one `RSA` row with 112 occurrences, not 112 rows); `--format html`
renders the same graph as a static page.

**Persistence** — behind a `Store` interface with two backends: a JSON file (any
path) and **Postgres** (a `postgres://` URL), persisting the graph into
normalized `scans`/`assets`/`occurrences` tables.

```bash
qryx scan --save 'postgres://user:pass@host:5432/db' <path>
qryx scan --baseline 'postgres://user:pass@host:5432/db' --fail-on-new high <path>
```

---

## Status

**Phase 0 and Phase 1 complete**, **Phase 2 in progress:**

- [x] static code scan · TLS probing · binary scanning (ELF/PE/Mach-O) · container images
- [x] cross-source CBOM asset graph · JSON/Postgres persistence · drift detection · CI gate
- [x] human / CBOM (CycloneDX 1.6) / HTML reports — all CI-gated
- [x] Phase 2 cloud KMS — AWS, GCP and Azure done
- [ ] Phase 3 — crypto-agility scoring and migration PRs

Roadmap and rationale: [`qryx-plan.md`](./qryx-plan.md).

## License

[Apache-2.0](./LICENSE).
