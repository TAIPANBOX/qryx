# qryx — Cryptography Security Graph

## Essence
A visibility and management layer for cryptography across code, infrastructure,
and clouds. qryx scans everything that uses crypto (code, binaries, TLS
connections, certificates, keys, cloud KMS, dependencies), stitches it into a
single **CBOM graph**, and answers a question few can answer quickly today:

> "Where exactly are we using vulnerable cryptography, what is at risk if it is
> compromised, and what is the minimal set of changes needed to migrate?"

The product is built as a platform: one core (ingest, graph, risk, remediation)
with many read-only connectors on the input side.

## Problem (with numbers)
1. **A hard regulatory deadline exists.** NIST PQC standards (FIPS 203/204/205,
   2024). CNSA 2.0: new national-security systems by 2027, legacy by 2030, full
   migration by 2035. EU / financial sector are following.
2. **Harvest-now-decrypt-later.** Data encrypted with RSA/ECC today can be
   collected now and decrypted later. The vulnerability is active today, not "in
   2030".
3. **Blindness at the start.** The first migration step is discovery, and
   organizations consistently find 3-5x more crypto assets than expected. "You
   can't migrate what you can't see."
4. **Tooling gap.** No general security platform provides CBOM/PQC migration; it
   requires purpose-built tooling. Existing solutions (SandboxAQ, Keyfactor,
   Venafi, IBM) are enterprise-priced. Mid-market + open-source is empty.

## Target buyer
- First: **platform / security engineers at mid-market** companies (fintech,
  SaaS, healthcare) for whom regulation or a customer audit requires a CBOM, but
  Wiz / SandboxAQ are out of budget.
- Then: GRC / compliance teams (reporting under CNSA 2.0 / EU / DORA) who pay for
  governance and evidence.

## Competitors and differentiation

| | Type | Segment | Weakness we exploit |
|---|---|---|---|
| SandboxAQ AQtive Guard | crypto-management | enterprise | expensive, closed, heavy onboarding |
| Keyfactor Command | PKI/cert lifecycle | enterprise | cert-centric, not a full CBOM |
| Venafi (CyberArk) | machine identity/certs | enterprise | about certificates, not crypto in code |
| IBM Quantum Safe Explorer | crypto discovery | enterprise | tied to the IBM ecosystem |

**qryx's gap (same as idryx):**
1. **Open-core** — OSS scanner + CBOM generator for adoption and self-hosting in
   regulated environments; paid: enforcement, governance, SaaS, reports.
2. **Mid-market / dev-first** — CLI + CI integration that installs in an hour;
   the big players target Fortune 1000.
3. **CBOM-native graph**, not cert-lifecycle with scanning bolted on: crypto in
   code, binaries, protocols, and cloud — in one model with impact paths.

Risk: a compliance-driven market (longer sales cycle), requires crypto-domain
expertise. Upside: the budget appears by force on the regulatory calendar, not on
hype — unlike the oversaturated AI-security space.

## What this is technically
- **CBOM** — Cryptography Bill of Materials in CycloneDX format (there is an
  official extension for crypto assets). Standard output → integrates into
  existing pipelines.
- **Discovery** — static analysis (crypto API calls, TLS config, hardcoded keys)
  + dynamic (active TLS handshake scans, certificate inspection) + inventory from
  cloud KMS / key stores.
- **Crypto-agility** — assessment of how easily a system can switch algorithms
  without a rewrite; recommends an abstraction layer where one is missing.

## Architecture

```
Sources (read-only connectors):
  Code repos (static crypto analysis)  ─┐
  Binaries / container images          ─┤
  TLS / network scans                  ─┤──► Ingest/normalize ──► CBOM graph
  Certificates (CT, endpoints)         ─┤                            │
  Key stores / HSM                     ─┤                            ▼
  Cloud KMS (AWS/GCP/Azure)            ─┤        Risk engine (vulnerable/weak/
  Dependencies (SBOM/crypto libs)      ─┘         misconfig/quantum-vulnerable)
                                                            │
                              ┌──────────────────────────────┤
                              ▼                               ▼
                       CBOM report / alerts           Crypto-agility recommendations
                       (CycloneDX, SIEM, GRC)         (PR to code/config, migration plan)
```

Same core as idryx: many connectors in → one normalized model → graph → risk →
remediation. Connectors differ, the engine is shared.

## Data model (sketch)
- **CryptoAsset** {type: key|cert|algorithm|protocol|library, algo, key_size,
  source, location, created, expires}
- **Usage** {asset, where (file/host/service), how (sign|encrypt|tls|hash), context}
- **Risk** {asset, class: quantum-vulnerable|weak|misconfig|expired|hardcoded, severity}
- **Relationship** edges: asset→usage, asset→dependency, asset→owner,
  usage→data_protected (what the asset is protecting).
- Queries: "all quantum-vulnerable assets protecting PII", "where is RSA <2048",
  "certificates expiring in 30 days and what signed them", "what breaks if TLS
  1.2 is disabled".

## Stack
- Scanners/core: **Go** (CLI, orchestration, connectors, TLS scans).
- Hot parsers (binaries, ASN.1/x509, protocols): **Rust** as needed.
- Analysis/reports/risk classification: **Python** if needed.
- Graph: Postgres first → graph DB if needed (like idryx).
- Output: CycloneDX CBOM, OTLP/SIEM, GRC reports.
- UI: **TypeScript** (React) — later.
- License: open-core (OSS scanner+CBOM, paid enforcement/governance/SaaS).

## Roadmap (phases)

### Phase 0 — CLI scanner + CBOM (2-3 weeks) — DONE
- Static scan of one repo: crypto calls, TLS config, hardcoded keys.
- CBOM output (CycloneDX) + human-readable report.
- Classification: quantum-vulnerable / weak / ok.
- **Go/no-go:** on a real repo, find something the owner didn't know in 10 min.

### Phase 1 — MVP discovery (1-1.5 months)
- tree-sitter instead of regex (accuracy, fewer false positives).
- Connectors: code + binaries/images + TLS scan of endpoints + certificates.
- CBOM graph in Postgres, asset deduplication across sources.
- Risk engine: full set of risk classes + severity.
- CI integration (fail on new vulnerable crypto) + basic web report.
- **Demo:** connect repo + domains → in an hour, a prioritized crypto-risk map.

### Phase 2 — Cloud KMS + dependencies (1.5 months)
- Connectors: AWS KMS/ACM, GCP KMS, Azure Key Vault; crypto libs from SBOM.
- Owner-mapping of assets; correlation "asset → what data it protects".
- Reports for CNSA 2.0 / audit.

### Phase 3 — Crypto-agility + remediation (1.5 months)
- Per-asset agility assessment; generate a migration plan prioritized by risk.
- PRs to code/Terraform: raise key size, replace algorithm, add a hybrid scheme.
- Explanation for each change (like the least-privilege diff in idryx).

### Phase 4 — Governance / enforcement (paid)
- Policies (forbid new RSA<3072, MD5, etc.) in blocking mode in CI.
- Continuous monitoring of crypto-posture drift.
- Compliance dashboards and evidence export.

## Monetization (open-core)
OSS: scanner + CBOM generator + basic risk (adoption, trust, self-hosting).
Paid: cloud connectors, crypto-agility/migration, CI enforcement, governance
dashboards, compliance reports, SaaS hosting. The check grows with inventory
scale and depth (discovery → migration → governance).

## Moat
- Accumulated crypto-usage patterns (discovery accuracy is data).
- Open-core community + connectors (like idryx).
- Shared core with idryx: two products, one engine — faster development of both.

## Risks
- Compliance-driven sales are slower than security-pain-driven → start with
  dev-first OSS adoption, monetize governance from the top.
- Regulatory deadlines can shift → don't tie the value proposition to a single
  date alone; harvest-now-decrypt-later remains an argument regardless.
- Cloud providers may add basic CBOM → focus on cross-platform correlation and
  remediation, not single-cloud inventory (same thesis as idryx).
- Crypto-domain complexity → start with a narrow, well-defined scope (TLS + code),
  expand incrementally.

## Next steps
1. Phase 1: replace regex with tree-sitter; introduce the Postgres CBOM graph.
2. Add the TLS endpoint scanner and certificate connector.
3. Validate on 2-3 real codebases: do we find what the owner didn't know?
