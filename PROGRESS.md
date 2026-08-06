# PROGRESS.md, where the qryx code actually is

A living log of implementation state, so a future session can pick up
mid-stream. This is the file that carries status; `CLAUDE.md` carries process
and invariants and deliberately carries no status at all.

Moved here from `CLAUDE.md` on 2026-07-31, unchanged except that long
dashes were normalized to short hyphens per the standing writing rule. It had been sitting
inside the instruction file with the heading "as of 2026-07-13", which is how
an instruction file goes stale: the reader trusts the whole document because
the process half of it is still correct.

**When you finish an increment, update this file, not `CLAUDE.md`.**

---

## Current status (as of 2026-07-13)

**Done:**
- Phase 0: static code scan (goast/cryptocall/certfile/tlsconfig/hardcoded/deps)
- Phase 1: TLS probing, ELF/PE/Mach-O binaries, container images, asset graph,
  CycloneDX CBOM, HTML report, Postgres + JSON persistence, CI drift gate
- Phase 2: `qryx aws`/`gcp`/`azure` connectors (interface seams, unit-tested
  without creds); owner-mapping via tags/labels; CNSA 2.0 audit (`--format cnsa`)
- Phase 3 increment 1: crypto-agility scoring (`internal/agility`) + risk-ranked
  migration plan (`--format migration`)
- Phase 3 increment 2: safe code remediation (`internal/remediate`, `qryx fix`) -
  raises sub-floor RSA key sizes via AST literal rewrite; dry-run diff by default,
  `--write` to apply. Only provably-safe transforms; algorithm swaps stay guidance.
- Phase 3 increment 3: `qryx fix --open-pr` - applies on a fresh branch and opens
  a GitHub PR via git+gh, guarded by a clean-tree check. git/gh behind a `Runner`
  interface seam, orchestration table-tested with a fake; the live git/gh path is
  unverified by design (don't run `--open-pr` against this repo - it makes a real PR).

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
- Phase 4 increment 2: drift-gated policy - `--policy ... --baseline X
  --policy-new-only` evaluates only `delta.Added` (new assets vs the baseline),
  so existing debt is grandfathered while new weak crypto still fails CI.
- Phase 4 increment 3: evidence export - `--format evidence` emits a CNSA 2.0
  compliance attestation (metadata + summary + per-asset + sha256 content digest
  with the digest field blanked, verifiable without keys). Reuses cnsa.go's
  `buildEntries`; counts match `--format cnsa`.
- Phase 4 increment 4: governance dashboard - `--format dashboard` (self-contained
  HTML) aggregates compliance score + severity profile + evidence digest + top
  remediation priorities. Reuses extracted `buildEvidence` (evidence.go) and
  `rankedSteps` (migration.go) so it can't disagree with cnsa/migration/evidence.
- Phase 4 increment 5: evidence trail - `--save-evidence <file.jsonl>` appends a
  compact digest-stamped record (via `report.Attest` + `store.JSONLTrail`,
  append-only `Trail` interface); `qryx trend <file>` renders history + score
  delta. report->store already exists, so the record is built in main to avoid
  an import cycle.
- Phase 4 increment 6: Postgres evidence trail - `store.PostgresTrail` (evidence
  table, shared `pgConnect`) behind the same `Trail` interface; `openTrail`
  picks JSONL vs Postgres by `postgres://`. Integration-tested under the
  `integration` build tag (CI postgres:16). Local run needs DATABASE_URL/docker.
- Phase 4 increment 7: evidence signing - `internal/attest` (stdlib ed25519 /
  ECDSA P-256, PKCS#8). `--format evidence --sign-key key.pem` adds a detached
  signature over the digest (embeds SPKI public key); `qryx verify-evidence`
  recomputes the digest and verifies. Pure attest pkg table-tested; live
  openssl keys verified end-to-end.

- Phase 4 increment 8: trend monitoring - `qryx trend --html` renders a
  self-contained SVG score chart (`report.TrendHTML`); `qryx trend
  --fail-on-regression` exits 3 when the latest score is below the previous run
  (CI monitor). html/template escapes `+` to `&#43;` - assert on unescaped text.

**Status: Phases 0-4 complete.** Governance is end-to-end: discover -> graph ->
CBOM/CNSA -> policy gate (+drift) -> remediation (fix/PR) -> evidence
(export/sign/verify/dashboard/trail/trend).

- Phase 4 increment 9: HCL-accurate Terraform detector - rewrote
  `internal/scan/detectors/terraform.go` onto `hashicorp/hcl/v2` (hclsyntax);
  added `google_kms_crypto_key`. The zero-dep bias was relaxed for this with the
  user's explicit approval (HCL parsing can't be done correctly with regex).

- Phase 4 increment 10: NCSC PQC readiness report - `--format ncsc|ncsc-html`
  (internal/report/ncsc.go) tracks the NCSC migration timeline (2028 discovery /
  2031 highest-priority / 2035 full) against the shared asset graph, with
  deterministic on-track/at-risk/not-started verdicts. 2031 subset = quantum-
  vulnerable AND (externally-facing via tls-probe/aws-acm OR long-lived-data via
  encryption/key-exchange primitives); criteria string embedded in both outputs.
  Migrated-count honestly stubbed at 0 (no per-scan remediation state; trail/
  trend is the progress mechanism).

- Phase 4 increment 11: `agility.target()` gained an Ed25519 case (maps to
  ML-DSA (FIPS 204), same as ECDSA/DSA - signature-to-signature) so Ed25519
  now counts as "planned" in the migration/NCSC reports. The NCSC at-risk
  fixture that used to lean on the Ed25519 gap (`ncsc_test.go`,
  `TestNCSCVerdicts`) now uses a synthetic SM2 finding (Risk set directly,
  bypassing risk.Classify) to keep exercising the "quantum-vulnerable with no
  agility target" branch.

- Phase 4 increment 12: `qryx agents` - `internal/agentstack` connector
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

- ML-DSA (FIPS 204) signing: `internal/attest` gained a third case (ed25519 /
  ECDSA P-256 / ML-DSA) using stdlib `crypto/mldsa`, which shipped its API
  frozen in Go 1.27rc2 well ahead of GA (expected ~August 2026). `go.mod`
  bumped to `go 1.27` / `toolchain go1.27rc2` -- a deliberate, user-approved
  call to build against the RC now rather than wait weeks for GA or pull in
  a third-party bridge library, since RC2 only takes bug/security fixes
  before GA, not API changes. All three security levels (`ML-DSA-44/65/87`)
  accepted, unlike the single P-256 curve ECDSA is restricted to -- they are
  equally standardized, safe choices, not one recommended option among
  weaker alternatives. Live end-to-end verified against real
  `openssl genpkey -algorithm ML-DSA-44` keys, including one real
  interoperability gotcha caught only by that live test: OpenSSL's default
  PKCS#8 output encodes both the seed and the expanded key, which Go's
  `x509.ParsePKCS8PrivateKey` rejects; generating with
  `-provparam ml-dsa.output_formats=seed-only` is required and is now
  documented in both the `--sign-key` flag help and the README.

- Agent-event export: `internal/exporter` (new package, wraps
  `github.com/TAIPANBOX/agent-stack-go/event`) emits `crypto_finding` /
  `crypto_drift` / `policy_violation` / `evidence_signed`
  (agent-passport SPEC.md §6.2's qryx row) as `taipanbox.dev/agent-event/
  v0.1` NDJSON, `source: "qryx"` -- qryx is one of the spec's original four
  (closed source enum), not a wave-2 service, so it stays on v0.1 rather
  than moving to v0.2 like Wardryx/Verdryx/Mockryx. This is the emitter
  half of SPEC.md §9's Qryx adoption row; `qryx agents`
  (`internal/agentstack`) already shipped the consumer half
  (`agent_id`-as-evidence-subject). New `--events <path>` flag; wired into
  the existing `res.Findings` / `delta.Added` / `policy.Evaluate`
  / `report.Evidence` call sites already computed for other output, not
  new detection logic. `agent_id` comes from `Tags["agent_id"]`,
  set only by `internal/agentstack`'s passport findings (`findingTags`,
  renamed from `ownerTags`) -- every other source's Tags has no agent
  concept, so `--events` is correctly a no-op there, never a fabricated
  subject. `policy.Violation` gained a `Tags` field (threaded through from
  the `graph.AssetNode` each violation was scored against) so
  `policy_violation` events can find their subject the same way;
  `report.Evidence`'s signature changed to also return the resulting
  `*attest.Signature`, so `evidence_signed` doesn't need to re-sign the
  digest a second time. Live end-to-end verified for all four event types
  against the real `internal/agentstack/testdata` fixtures via the actual
  compiled CLI, not just unit tests -- including confirming
  `policy_violation` correctly emits only for the one violation with a
  real agent_id even when the human-readable report shows two.

- Test/production separation: crypto found in test code (`_test.go`,
  `testdata/`, `__tests__/`, `conftest.py`, `*.spec.ts`, ...) is classified at
  walk time (`internal/scan/testpath.go`, stamped onto `model.Location.IsTest`
  by the walker so no detector can forget) and split out ONCE in the shared
  tail of `cmd/qryx/main.go` via `scan.PartitionTests`, before the graph,
  `--save`, `--events`, the policy gate and every `--format` read the findings.
  So they cannot disagree about what production means. Excluded by default,
  `--include-tests` restores the old behaviour; a stderr line always says how
  much was set aside and how many assets exist only there (identity via
  `graph.AssetKey`, never a hand-rolled key, so risk class stays part of it).
  Measured on this repo: 13 assets -> 5 and 40 occurrences -> 19, with 8 assets
  existing only in fixtures. `examples/` is deliberately NOT test code: example
  code is shipped and copied. Non-filesystem sources (tls/bin/image/cloud) are
  always production, which is the correct zero value.

- 2026-08-05, "could not look" is no longer reported as "found nothing" (branch
  `fix/no-silent-clean-results`): three defects from a read-only audit, all the
  same disease. (1) Both drift gates failed open when the baseline was missing:
  a baseline that could not be loaded produced an empty delta, so
  `--fail-on-new` iterated nothing and `--policy --policy-new-only` gated an
  empty node set, both exiting 0. Now an error naming the path whenever a gate
  reads the comparison, with `--allow-missing-baseline` as the explicit opt-in
  for a first run. (2) The walker returned bare `nil` for unreadable entries,
  failed `Info()` calls, files over `scan.MaxFileSize` and failed reads, and
  `FilesWalked` counted only the survivors; `goast` and `certfile` swallowed
  parse failures the same way. `scan.Result` now carries `Unreadable`,
  `Oversize` and `Unparsed`, the last via the optional
  `scan.UnparsedReporter` seam, and `cmd/qryx` prints them on stderr beside the
  test-code line, silently when they are all zero. (3) `qryx image` buffered
  each outer tar entry to a 32 MiB cap before sniffing it as a layer, so any
  realistic image was truncated into `io.ErrUnexpectedEOF` and reported as
  clean with exit 0; layers now stream through the tar reader (the cap no
  longer bounds a layer at all, only a single file inside one, which is skipped
  and counted rather than truncated), and a failed extraction is fatal and
  names the image. `maxFileBytes` became a package var purely so a test can
  drive a layer past the cap with kilobytes instead of 32 MiB in CI.
  *(@measured: `go test -race ./...`, the three gate scripts, and the real
  binary against a synthetic 40 MiB image that scans as 0 findings on
  567c2ce and reports its MD5 finding after, 2026-08-05)*

- 2026-08-06, Terraform-declared assets are scored as configuration, and an
  unrankable source is no longer dropped in silence (branch
  `fix/agility-terraform-source`). `internal/agility`'s `sourceAgility` map had
  no row for `terraform`, and `dominantAgility` recorded a source name only
  inside the branch that recognised it, so one missing row cost two answers at
  once. Every HCL-declared key scored `low`, "code change + redeploy", when a
  key spec in HCL is changed by editing an argument and running `apply`, which
  is what `medium` means in that file -- and the same physical key read back
  through the AWS, GCP or Azure connector scored `high`, so its difficulty
  depended on which connector saw it. The name was dropped from the effort note
  as well, which printed an empty parenthesis. Four rows were missing in all:
  `terraform` and `agentstack` (medium), `rust` and `aiusage` (low); the last
  two emit no asset `target()` maps today, so their level is unexercised and
  the rows exist to keep the lists reconciled. An unrecognised source now
  counts as `low` whatever its company, rather than as `low` alone and as
  nothing at all beside a known source. Both halves of the list are now held
  structurally by `internal/agility/sources_test.go`: one test walks
  `detectors.Default()`, the other reads every `Source: "..."` literal out of a
  `model.Finding` composite literal in the tree, so a connector cannot ship
  without a row again.
  *(@measured: `qryx scan --format migration testdata/sample` on `main` at
  515864e prints `"agility": "low"` with `"effort": "code change + redeploy ();
  1 occurrence(s)"` for all three `main.tf` entries (lines 3, 8 and 16) and
  `"config/dependency change (terraform); 1 occurrence(s)"` at `"medium"` after.
  `summary.toMigrate` stays 6 and `summary.quickWins` stays 0, since a quick win
  needs `high` agility; plan order shifts, the RSA-2048 `main.tf:16` entry
  moving from priority 5 to 4 ahead of MD5 because agility ranks after severity.
  `go test -race ./...` and the three gate scripts pass; tests badge 197 -> 203,
  2026-08-06)*

**No remaining deliberate deferrals** -- both items tracked here (ML-DSA
signing, agent-event export) are done. Revisit `go.mod`'s
`toolchain go1.27rc2` pin once Go 1.27 GA ships, to drop the
release-candidate requirement.

