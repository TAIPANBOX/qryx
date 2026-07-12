# CLAUDE.md — working instructions for qryx

These instructions apply to any model working in this repo. They encode the
process and patterns the project was built with so work stays consistent
regardless of which model is active. Read this before starting a task.

## What qryx is
A CLI that inventories cryptography across sources (code, binaries, container
images, live TLS, certs, dependencies, cloud KMS), normalizes it into one
**cryptographic asset graph**, scores post-quantum + hygiene risk, and emits
CycloneDX CBOM / human / HTML reports with JSON/Postgres persistence and CI
drift gating. Pure-Go bias; stdlib first. Product plan and roadmap:
[`qryx-plan.md`](./qryx-plan.md).

## Current status (as of 2026-07-10)

**Done:**
- Phase 0: static code scan (goast/cryptocall/certfile/tlsconfig/hardcoded/deps)
- Phase 1: TLS probing, ELF/PE/Mach-O binaries, container images, asset graph,
  CycloneDX CBOM, HTML report, Postgres + JSON persistence, CI drift gate
- Phase 2: `qryx aws`/`gcp`/`azure` connectors (interface seams, unit-tested
  without creds); owner-mapping via tags/labels; CNSA 2.0 audit (`--format cnsa`)
- Phase 3 increment 1: crypto-agility scoring (`internal/agility`) + risk-ranked
  migration plan (`--format migration`)
- Phase 3 increment 2: safe code remediation (`internal/remediate`, `qryx fix`) —
  raises sub-floor RSA key sizes via AST literal rewrite; dry-run diff by default,
  `--write` to apply. Only provably-safe transforms; algorithm swaps stay guidance.
- Phase 3 increment 3: `qryx fix --open-pr` — applies on a fresh branch and opens
  a GitHub PR via git+gh, guarded by a clean-tree check. git/gh behind a `Runner`
  interface seam, orchestration table-tested with a fake; the live git/gh path is
  unverified by design (don't run `--open-pr` against this repo — it makes a real PR).

- Terraform: `terraform` detector (`.tf`: `tls_private_key`, `aws_kms_key`,
  `azurerm_key_vault_key`, `google_kms_crypto_key`) feeds the shared graph;
  `tf-rsa-bits` remediation rule raises weak `rsa_bits` via `qryx fix`. Uses the
  `hashicorp/hcl/v2` parser (hclsyntax): reads well-known crypto attributes,
  evaluates only static expressions, treats variables/interpolation as unknown
  (size 0) rather than guessing. Heredoc/string text no longer false-matches.
- Phase 4 increment 1: policy engine (`internal/policy`) + `--policy <name|file>`
  CI gate. Builtin `cnsa` + JSON files; evaluates the deduped graph, prints
  violations to stderr, exits 3 (distinct from `--fail-on`'s 2). stdout format
  output stays clean. Pure `Evaluate`, table-tested.
- Phase 4 increment 2: drift-gated policy — `--policy ... --baseline X
  --policy-new-only` evaluates only `delta.Added` (new assets vs the baseline),
  so existing debt is grandfathered while new weak crypto still fails CI.
- Phase 4 increment 3: evidence export — `--format evidence` emits a CNSA 2.0
  compliance attestation (metadata + summary + per-asset + sha256 content digest
  with the digest field blanked, verifiable without keys). Reuses cnsa.go's
  `buildEntries`; counts match `--format cnsa`.
- Phase 4 increment 4: governance dashboard — `--format dashboard` (self-contained
  HTML) aggregates compliance score + severity profile + evidence digest + top
  remediation priorities. Reuses extracted `buildEvidence` (evidence.go) and
  `rankedSteps` (migration.go) so it can't disagree with cnsa/migration/evidence.
- Phase 4 increment 5: evidence trail — `--save-evidence <file.jsonl>` appends a
  compact digest-stamped record (via `report.Attest` + `store.JSONLTrail`,
  append-only `Trail` interface); `qryx trend <file>` renders history + score
  delta. report->store already exists, so the record is built in main to avoid
  an import cycle.
- Phase 4 increment 6: Postgres evidence trail — `store.PostgresTrail` (evidence
  table, shared `pgConnect`) behind the same `Trail` interface; `openTrail`
  picks JSONL vs Postgres by `postgres://`. Integration-tested under the
  `integration` build tag (CI postgres:16). Local run needs DATABASE_URL/docker.
- Phase 4 increment 7: evidence signing — `internal/attest` (stdlib ed25519 /
  ECDSA P-256, PKCS#8). `--format evidence --sign-key key.pem` adds a detached
  signature over the digest (embeds SPKI public key); `qryx verify-evidence`
  recomputes the digest and verifies. Pure attest pkg table-tested; live
  openssl keys verified end-to-end.

- Phase 4 increment 8: trend monitoring — `qryx trend --html` renders a
  self-contained SVG score chart (`report.TrendHTML`); `qryx trend
  --fail-on-regression` exits 3 when the latest score is below the previous run
  (CI monitor). html/template escapes `+` to `&#43;` — assert on unescaped text.

**Status: Phases 0-4 complete.** Governance is end-to-end: discover -> graph ->
CBOM/CNSA -> policy gate (+drift) -> remediation (fix/PR) -> evidence
(export/sign/verify/dashboard/trail/trend).

- Phase 4 increment 9: HCL-accurate Terraform detector — rewrote
  `internal/scan/detectors/terraform.go` onto `hashicorp/hcl/v2` (hclsyntax);
  added `google_kms_crypto_key`. The zero-dep bias was relaxed for this with the
  user's explicit approval (HCL parsing can't be done correctly with regex).

- Phase 4 increment 10: NCSC PQC readiness report — `--format ncsc|ncsc-html`
  (internal/report/ncsc.go) tracks the NCSC migration timeline (2028 discovery /
  2031 highest-priority / 2035 full) against the shared asset graph, with
  deterministic on-track/at-risk/not-started verdicts. 2031 subset = quantum-
  vulnerable AND (externally-facing via tls-probe/aws-acm OR long-lived-data via
  encryption/key-exchange primitives); criteria string embedded in both outputs.
  Migrated-count honestly stubbed at 0 (no per-scan remediation state; trail/
  trend is the progress mechanism).

- Phase 4 increment 11: `agility.target()` gained an Ed25519 case (maps to
  ML-DSA (FIPS 204), same as ECDSA/DSA — signature-to-signature) so Ed25519
  now counts as "planned" in the migration/NCSC reports. The NCSC at-risk
  fixture that used to lean on the Ed25519 gap (`ncsc_test.go`,
  `TestNCSCVerdicts`) now uses a synthetic SM2 finding (Risk set directly,
  bypassing risk.Classify) to keep exercising the "quantum-vulnerable with no
  agility target" branch.

- Phase 4 increment 12: `qryx agents` — `internal/agentstack` connector
  inventories the agent-governance stack's own trust surface (Agent Passport
  attestation crypto + agent-event NDJSON hash-chain integrity), per
  `agent-passport/SPEC.md` §4/§6; identity/privilege stays Idryx's job.

- `binscan`: ELF detector now resolves OpenSSL 3.x's primary `EVP_*` API
  (`EVP_aes_*`, `EVP_des_*`, `EVP_md5/sha1/sha224/256/384/512` fetch names,
  `EVP_PKEY_CTX_set_*` asymmetric keygen setters), not just the legacy flat
  API (`RSA_new`, `MD5_Init`, ...). Scanning a modern `/usr/bin/openssl`
  found almost nothing before this fix; verified against the real symbol
  set via `nm -D`. Added libgcrypt to the known crypto-library list
  (commit ce21060).

- Graph dedup fix: `graph.AssetNode`'s identity (`key`, and the exported
  `graph.AssetKey`) now includes risk class alongside type/algo/key size, so
  a physical asset carrying two orthogonal risks (e.g. a certificate that is
  both expired and quantum-vulnerable) produces two nodes instead of one
  silently overwriting the other. Verified live against
  `expired.badssl.com`: `qryx tls` was reporting "0 expired" even though the
  finding existed, its evidence folded into the RSA node instead of getting
  its own risk class. `internal/store`'s baseline/drift diffing updated to
  match the new `AssetKey` signature (commit e06d605).

- README: added a "Where this fits in the stack" section (shared TAIPANBOX
  cross-service diagram plus this repo's consumes/produces/talks-to card),
  so a reader landing on this repo gets the whole agent-governance workflow
  from one service README (commit f6ed691).

- `agentstack`: `qryx agents` now accepts agent-event schema `v0.2`
  (Wardryx/Mockryx/Verdryx's emitted schema, differing from `v0.1` only in
  the `source` field per `agent-passport/SPEC.md` §6.4) alongside `v0.1`.
  Before this fix, any file containing only `v0.2` events parsed to zero
  events and was silently skipped as unrecognized (commit ef364ba).

- README: stack diagram now shows Mockryx's and Verdryx's bus-emission
  edges (both emit agent-event `v0.2` to the shared bus), matching what the
  services actually do (commit d8f5fbe).

**Remaining (deliberate deferrals, not tech debt):**
1. ML-DSA (FIPS 204) signing — once Go stdlib ships it (attest pkg is ready for
   a new alg).

**Ask the user which to tackle first at the start of a new session.**

## The working loop (follow every time)
1. **Plan Mode first** for anything touching multiple files or making an
   architectural/dependency decision. Write the plan, get the user's approval,
   then implement. Small single-file fixes can skip it.
2. **Implement** one logical increment. Match surrounding style; comments only
   where the *why* is non-obvious.
3. **Gates — all must pass before saying done:**
   `go build ./... && gofmt -l . && go vet ./... && go test -race ./...`
4. **Verify end-to-end** when possible: build `/tmp/qryx` and run the real
   command on fixtures or a real target.
5. **Commit** one logical change, Conventional Commits (`feat:`/`fix:`/`test:`/
   `docs:`/`refactor:`/`chore:`), end with the `Co-Authored-By` trailer.
6. **Push** to `origin/main` (GitHub `TAIPANBOX/qryx`).
7. **Check CI**: `gh run list --branch main --limit 1`; wait for it; both `build`
   and `integration` jobs must be green. Fix forward if red.

## Architecture & conventions (reuse these — do not reinvent)
- **One model:** every connector produces `model.Finding` (internal/model).
  Risk left empty → classified centrally by `risk.Classify`/`risk.Apply`;
  context findings (TLS misconfig, expiry, hardcoded) set their own `Risk`.
- **Connector pattern:** sources that don't fit the file walker (TLS, binaries,
  images, cloud) are **separate packages + a CLI subcommand** that returns a
  `*scan.Result`, mirroring `internal/probe`, `internal/binscan`,
  `internal/imagescan`, `internal/cloud/aws`, `internal/cloud/gcp`. Add the
  command in `cmd/qryx/main.go`; the shared tail handles `--format` /
  `--save` / `--baseline` / `--fail-on*`.
- **Interface seam for external SDKs** (cloud, anything needing creds): define a
  tiny interface the real client satisfies, put the mapping logic behind it, and
  unit-test with a fake. The pure algorithm→asset mapper is always table-tested.
  Only the thin real-SDK wiring stays unverified when no account is available —
  say so explicitly.
- **Graph:** findings dedup into `graph.AssetNode` by `graph.AssetKey`
  (type + normalized algo + key size + risk class). Risk class is part of
  node identity, not just an attribute: an algorithm property (e.g. RSA is
  quantum-vulnerable) and a validity/hygiene state (e.g. a cert is expired)
  are orthogonal, so the same physical asset legitimately gets two nodes
  instead of one silently overwriting the other (commit e06d605). Any code
  that derives its own identity/hash from asset fields (a reporter's
  bom-ref, a new connector's own dedup) must include risk class too, or two
  distinct nodes will silently collide back into one: exactly the bug in
  `internal/report/cbom.go`'s `bomRef()`, fixed to match. Reporters consume
  the graph, not raw findings.
- **Zero-dependency bias:** prefer stdlib (`debug/elf|pe|macho`, `archive/tar`,
  `crypto/tls`, `html/template`). Add a dependency only when unavoidable (pgx,
  cloud SDKs, `hashicorp/hcl/v2` for correct Terraform parsing) and justify it
  in the plan.
- **Detector philosophy:** signal quality over recall. Resolve real imports/
  symbols (AST, ELF dynsyms), don't scrape strings; keep false positives low.

## Known pitfalls (already cost us once)
- **Map order in fakes/pagination:** Go randomizes map iteration; never derive a
  stable order from `range map` across calls. Sort into a slice. Run
  `go test -race -count=5 ./pkg/` on pagination fakes — this flaked CI once.
- `InsecureSkipVerify` + low `MinVersion` in `internal/probe` are **intentional**
  (it inspects TLS posture, doesn't trust it). Don't "fix" them.
- CLI flags must precede positionals (`qryx scan [flags] <path>`); Go `flag`
  stops at the first positional.
- The repo is **private**; README badges/images only render for users with access.
- Security extraction (`imagescan`): keep the path-traversal/symlink/tar-bomb
  guards; never follow links out of the temp root.

## Escalate to Opus 4.8 — tell the user, don't just push through
You (any model) cannot switch models. When a task hits the high-stakes criteria
below, **stop and print this line, then wait** for the user to switch or say go:

> `MODEL CHECK: recommend Opus 4.8 — <one-line reason>. Switch now, or proceed on the current model?`

Escalate when the task involves:
- A real architectural fork with expensive rollback (new persistence layer, new
  cross-cutting abstraction, changing the asset/graph model).
- Untangling a conflict or anything **irreversible/outward-facing** (history
  rewrite, force-push, deleting work you didn't create, making the repo public).
- Subtle correctness reasoning where a missed case ships a wrong answer
  (risk-classification edge cases, dedup/graph identity, security guards).
- A multi-step debugging session where the root cause isn't obvious.

Routine increments are fine on Sonnet 4.6: a new connector following the
established pattern, PE/Mach-O-style symmetric extensions, tests, docs, CLI
wiring, dependency bumps. The Plan-Mode-then-approve loop already puts a human
gate in front of the risky decisions, which keeps quality high on any model.

## Memory
Session learnings live in `~/.claude/projects/-Users-factory-Development-Qryx/memory/`
(see `MEMORY.md`). Check it for prior lessons before repeating a class of mistake.
