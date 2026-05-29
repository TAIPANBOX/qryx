# qryx — Cryptography Security Graph

Organization-wide cryptography inventory and management: what is encrypted,
where, and with which algorithm; which of those assets are quantum-vulnerable;
and how to migrate them. Open-core, dev-first, built for mid-market.

> Sibling product to [idryx](https://github.com/TAIPANBOX/idryx) (Identity
> Security Graph). Shared architectural DNA: **X-BOM → graph → risk →
> remediation**. idryx does this for identities, qryx for cryptography.

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
./bin/qryx scan <path>                 # human-readable report
./bin/qryx scan --format cbom <path>   # CycloneDX 1.6 CBOM (JSON)
./bin/qryx scan --fail-on high <path>  # exit 2 if any finding >= high (for CI)
```

Run against the bundled fixtures:
```bash
make scan
```

## What works today (Phase 0)
A single-tree CLI scanner with 5 detectors:
- `cryptocall` — crypto API usage in source (Go / Python / JS / TS)
- `certfile` — PEM certificate parsing (algorithm, key size, expiry)
- `tlsconfig` — legacy TLS/SSL in code and nginx/apache config
- `hardcoded` — private keys embedded in source/config
- `deps` — crypto libraries in dependency manifests

Risk classification: `quantum-vulnerable` (RSA/ECC/DSA — Shor), `weak`
(MD5/SHA-1/DES/RC4, RSA<2048), `misconfig`, `expired`, `hardcoded`. Post-quantum
algorithms (ML-KEM/ML-DSA, FIPS 203/204/205) are recognized as safe.

## Status
Phase 0 (MVP CLI scanner) — working. Next, per [`qryx-plan.md`](./qryx-plan.md):
tree-sitter instead of regex, a CBOM graph in Postgres, active TLS scanning,
cloud KMS connectors.

## License
Apache-2.0.
