# qryx — Cryptography Security Graph

Organization-wide cryptography inventory and management: what is encrypted,
where, and with which algorithm; which of those assets are quantum-vulnerable;
and how to migrate them. Open-core, dev-first, built for mid-market.

## Why
NIST standardized post-quantum algorithms (2024); CNSA 2.0 sets the deadlines
(new systems 2027, legacy 2030, full migration 2035). "Harvest now, decrypt
later" means data encrypted with vulnerable crypto is already compromised today.
The first step of any migration is discovery, and organizations consistently find
3-5x more cryptographic assets than expected. Off-the-shelf mid-market /
open-source tooling for this barely exists — every vendor is enterprise-priced.

## What it does
1. **Discovery** — scans code, binaries, TLS/network, certificates, key stores,
   cloud KMS, and dependencies; finds every use of cryptography.
2. **CBOM** — builds a Cryptography Bill of Materials (CycloneDX) in one graph.
3. **Risk** — flags quantum-vulnerable (RSA/ECC), weak (MD5/SHA-1/DES),
   misconfig, expired certificates, hardcoded keys.
4. **Crypto-agility / remediation** — migration recommendations + PRs to
   code/config.

See [`qryx-plan.md`](./qryx-plan.md) for the full design and roadmap.

## Quick start
```bash
make build
./bin/qryx scan <path>                 # static scan of a code tree
./bin/qryx scan --format cbom <path>   # CycloneDX 1.6 CBOM (JSON)
./bin/qryx scan --format html <path> > report.html   # self-contained web report
./bin/qryx scan --fail-on high <path>  # exit 2 if any finding >= high (for CI)

./bin/qryx tls example.com:443         # probe a live endpoint's TLS posture
./bin/qryx tls --timeout 3s host:443   # version, cipher suite, certificate key

./bin/qryx bin /usr/bin/openssl        # crypto in a binary (ELF/PE/Mach-O)
./bin/qryx bin ./build/                 # walk a dir, scan every binary

docker save myapp:latest -o img.tar && ./bin/qryx image img.tar  # scan an image

./bin/qryx scan --save base.json <path>              # snapshot the asset graph
./bin/qryx scan --baseline base.json <path>          # report drift vs baseline
./bin/qryx scan --baseline base.json --fail-on-new high <path>  # CI: block new crypto
```

> Flags must precede the positional path/targets (`qryx scan [flags] <path>`).

> `qryx tls` actively connects to the targets you pass — only the exact
> `host:port` arguments, no port ranges or host discovery. Probe only endpoints
> you are authorized to test.

Run against the bundled fixtures:
```bash
make scan
```

## What works today
Static scan of a code tree (`qryx scan`) with 6 detectors:
- `goast` — crypto usage in Go via AST import resolution (no regex false positives)
- `cryptocall` — crypto API usage in Python / JS / TS source
- `certfile` — PEM certificate parsing (algorithm, key size, expiry)
- `tlsconfig` — legacy TLS/SSL in code and nginx/apache config
- `hardcoded` — private keys embedded in source/config
- `deps` — crypto libraries in dependency manifests

Active TLS probing of live endpoints (`qryx tls`): negotiated TLS version,
insecure cipher suites, and the leaf certificate's public-key algorithm, size,
and expiry — fed into the same risk model and CBOM output.

Binary scanning (`qryx bin`): parses ELF, PE and Mach-O via `debug/elf|pe|macho`,
mapping needed crypto libraries (libcrypto/libssl/…) and imported symbols
(`MD5_*`, `RSA_*`, `ECDSA_*`, …) to assets — no string scraping, low false
positives. Format is chosen by magic bytes; non-binaries are skipped.

Container image scanning (`qryx image`): extracts a local image tarball
(`docker save` / OCI layout) with stdlib tar/gzip — guarded against path
traversal and tar bombs — and runs the code and binary scanners over the layers.
No registry pull, no extra dependencies.

Findings from every source are aggregated into a **cryptographic asset graph**:
one node per logical asset (algorithm + key size) carrying all of its
occurrences, deduplicated across files and sources. The CBOM emits one CycloneDX
component per asset with every occurrence listed, and the human report shows
asset-level counts (e.g. one `RSA` row with 112 occurrences, not 112 rows). The
same graph also renders as a self-contained HTML report (`--format html`): risk
chips plus a per-asset table with collapsible occurrence lists.

The graph can be saved as a snapshot (`--save`) and a later scan compared
against it (`--baseline`) to surface **drift** — assets newly introduced or
removed. `--fail-on-new <severity>` exits non-zero when a scan introduces a new
asset at or above that severity, the CI hook for "don't add new weak crypto".

Persistence is behind a `Store` interface with two backends: a JSON file (any
plain path) and **Postgres** (a `postgres://` URL), which persists the graph in
normalized `scans`/`assets`/`occurrences` tables.

```bash
./bin/qryx scan --save 'postgres://user:pass@host:5432/db' <path>
./bin/qryx scan --baseline 'postgres://user:pass@host:5432/db' --fail-on-new high <path>
```

Risk classification: `quantum-vulnerable` (RSA/ECC/DSA — Shor), `weak`
(MD5/SHA-1/DES/RC4, RSA<2048), `misconfig`, `expired`, `hardcoded`. Post-quantum
algorithms (ML-KEM/ML-DSA, FIPS 203/204/205) are recognized as safe.

## Status
**Phase 0 and Phase 1 complete:** static code scan, active TLS probing, binary
scanning (ELF/PE/Mach-O), container-image scanning, a cross-source CBOM asset
graph, JSON/Postgres persistence with drift detection, and human/CBOM/HTML
reports — all CI-gated. Next, per [`qryx-plan.md`](./qryx-plan.md): Phase 2
(cloud KMS connectors — AWS/GCP/Azure) and Phase 3 (crypto-agility and migration
PRs). Possible hardening: tree-sitter instead of regex for Python/JS.

## License
Apache-2.0.
