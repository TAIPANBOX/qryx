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

## Current status (as of 2026-05-31)

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
  `azurerm_key_vault_key`) feeds the shared graph; `tf-rsa-bits` remediation rule
  raises weak `rsa_bits` via `qryx fix`. Regex + brace-matched block scan (no HCL
  dep, per zero-dep bias); precision over recall.
- Phase 4 increment 1: policy engine (`internal/policy`) + `--policy <name|file>`
  CI gate. Builtin `cnsa` + JSON files; evaluates the deduped graph, prints
  violations to stderr, exits 3 (distinct from `--fail-on`'s 2). stdout format
  output stays clean. Pure `Evaluate`, table-tested.

**Next (in priority order per qryx-plan.md):**
1. Phase 4 cont.: drift-gated policy (fail only on NEW violations vs `--baseline`,
   reuse `store.Diff`); compliance dashboards / evidence export; continuous monitoring.
2. Detector depth: HCL-accurate parsing (heredocs/interpolation), `google_kms_*`
   template algorithms.

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
  (type + normalized algo + key size). Reporters consume the graph, not raw
  findings.
- **Zero-dependency bias:** prefer stdlib (`debug/elf|pe|macho`, `archive/tar`,
  `crypto/tls`, `html/template`). Add a dependency only when unavoidable (pgx,
  cloud SDKs) and justify it in the plan.
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
