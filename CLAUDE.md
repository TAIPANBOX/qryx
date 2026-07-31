# CLAUDE.md, working instructions for qryx

These instructions apply to any model working in this repo. Read this file
before starting a task. It holds process and invariants only: **no status.**
Status goes stale, and a stale instruction file is worse than none, because the
reader trusts the whole document on the strength of the half that is still
correct. Where the code actually is lives in `PROGRESS.md`.

## Read before you change anything

1. `qryx-plan.md`, the product plan and roadmap.
2. `PROGRESS.md`, for what is built.
3. The **Hard invariants** section below, before touching the graph, the asset
   identity, or anything with a security guard in it.

## What qryx is

A CLI that inventories cryptography across sources (code, binaries, container
images, live TLS, certs, dependencies, cloud KMS), normalizes it into one
**cryptographic asset graph**, scores post-quantum and hygiene risk, and emits
CycloneDX CBOM, human and HTML reports with JSON/Postgres persistence and CI
drift gating. Pure-Go bias, stdlib first.

This tool is defensive: it inventories an organization's own cryptography so it
can find its own weak spots. Never describe it as tooling for probing anyone
else's infrastructure.

## The working loop (follow every time)
1. **Plan Mode first** for anything touching multiple files or making an
   architectural/dependency decision. Write the plan, get the user's approval,
   then implement. Small single-file fixes can skip it.
2. **Implement** one logical increment. Match surrounding style; comments only
   where the *why* is non-obvious.
3. **Gates - all must pass before saying done:**
   `go build ./... && gofmt -l . && go vet ./... && go test -race ./...`
4. **Verify end-to-end** when possible: build `/tmp/qryx` and run the real
   command on fixtures or a real target.
5. **Commit** one logical change, Conventional Commits (`feat:`/`fix:`/`test:`/
   `docs:`/`refactor:`/`chore:`), end with the `Co-Authored-By` trailer.
6. **Push** to `origin/main` (GitHub `TAIPANBOX/qryx`).
7. **Check CI**: `gh run list --branch main --limit 1`; wait for it; both `build`
   and `integration` jobs must be green. Fix forward if red.

## Architecture & conventions (reuse these - do not reinvent)
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
  Only the thin real-SDK wiring stays unverified when no account is available -
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

## Hard invariants

Each one carries how it is held today. Use `(gate: ...)`, `(test: ...)`,
`(partly gated: ...)` or `(not enforced)`, and use the weakest one that is
true. An invariant with no check, written as though it had one, is worse than
an absent invariant.

1. **Risk class is part of asset-node identity, not an attribute of it.**
   `graph.AssetKey` is type plus normalized algorithm plus key size plus risk
   class. An algorithm property (RSA is quantum-vulnerable) and a validity or
   hygiene state (this certificate is expired) are orthogonal, so one physical
   asset legitimately becomes two nodes rather than one silently overwriting
   the other. **Any code deriving its own identity or hash from asset fields
   must include risk class**, or two distinct nodes collide back into one and
   the report quietly under-counts. This has already happened once, in
   `internal/report/cbom.go`'s `bomRef()`.
   *(test: `TestCBOMBomRefUniqueAcrossRiskClasses` is the regression test for
   that exact bug; `TestBuildPreservesOrthogonalRisksOnSameAsset` holds the
   graph-identity half; `TestCnsaStatusContextRiskWinsOverAlgorithmCompliance`
   and `TestCNSAJSONOutputSurfacesBothRisksOnExpiredQuantumVulnerableCert` hold
   the reporting half)*
2. **Reporters consume the graph, never raw findings.** The dedup and the risk
   classification happen once, centrally. A reporter that reaches back to
   findings is re-implementing both and will disagree with the others.
   *(not enforced)*
3. **Stdlib first.** A new dependency needs a justification in the plan and the
   user's agreement, not a commit. The current justified set is pgx, the cloud
   SDKs, and `hashicorp/hcl/v2` for correct Terraform parsing. *(not enforced)*
4. **External SDKs sit behind an interface seam, and the pure mapper is
   table-tested.** Only the thin real-SDK wiring may stay unverified when no
   account is available, and when it does, **say so explicitly** rather than
   letting a green test suite imply coverage it does not have.
   *(not enforced)*
5. **`InsecureSkipVerify` and the low `MinVersion` in `internal/probe` are
   deliberate.** The prober inspects TLS posture, it does not trust it. Do not
   "fix" them. A future hardening sweep that removes them breaks the tool's
   only job. *(not enforced)*
6. **A clean scan is not proof of absence, and must not be reported as one.**
   `binscan` sees only what has a symbol to read. A stripped, statically linked
   binary has neither crypto in `.dynsym` nor a `.symtab` fallback, and is
   invisible here; PE and Mach-O have no `.symtab`-style fallback at all. When
   this is relevant to a result, state it. *(not enforced)*
7. **The extraction guards in `imagescan` stay.** Path traversal, symlink
   escape and tar-bomb protection, and never following a link out of the temp
   root. These exist because the tool unpacks images it did not build.
   *(partly gated: `TestExtractRejectsPathTraversal` covers traversal. The
   symlink-escape and tar-bomb guards have no test of their own, and are the
   ones a hardening sweep would remove first.)*
8. **Never derive a stable order from map iteration.** Go randomizes it. Sort
   into a slice. This flaked CI once already, in pagination fakes.
   *(partly gated: `go test -race -count=5` on the affected packages, which
   only catches it where somebody remembered to run it that way)*

## Decisions that have no gate yet

This list is debt, and it is here to stay visible rather than to be tidy.
**A correction. This section previously said seven of the eight invariants were
held by this file alone, and singled out invariant 1 as deserving a test "more
than anything else here". Invariant 1 has four tests**, including
`TestCBOMBomRefUniqueAcrossRiskClasses`, which is the regression test written
for the exact `bomRef()` bug the invariant describes. The claim was made by
reading the code and never opening the suite.

The rule that follows: set a marker from evidence, both ways. Before writing
`(not enforced)`, grep the suite for the property. Before writing `(test: ...)`,
open the test and check it asserts what the invariant claims.

**Held by this file alone: invariants 2, 3, 4 and 6.** Invariants 7 and 8 are
half held.

Of those, only **invariant 3** is mechanically checkable: a dependency
allow-list, the same shape as the one in `agent-stack-go`, perhaps thirty
lines. Invariant 5 could be pinned by a test asserting the prober's TLS config
still carries its deliberately permissive settings, so a hardening sweep has to
argue with a red build rather than a code comment.

Invariants 2, 4 and 6 are judgement, and 6 in particular is about how a result
is described, which no script can read.

## Standing rule

An approved architecture decision is **not finished** until it is two things: a
numbered invariant in this file, and a gate in a script or a test if it can be
checked structurally. Until then it is a document, and documents do not stop
code.

When the user approves a decision, add it here in the same session. Do not
defer it, because later is where the drift lives.

## Known pitfalls (already cost us once)
- **Map order in fakes/pagination:** Go randomizes map iteration; never derive a
  stable order from `range map` across calls. Sort into a slice. Run
  `go test -race -count=5 ./pkg/` on pagination fakes - this flaked CI once.
- `InsecureSkipVerify` + low `MinVersion` in `internal/probe` are **intentional**
  (it inspects TLS posture, doesn't trust it). Don't "fix" them.
- CLI flags must precede positionals (`qryx scan [flags] <path>`); Go `flag`
  stops at the first positional.
- The repo is **public** (Apache-2.0). Anything written here, including code
  comments and commit messages, is published. This line previously said
  private, which was true once and stopped being true; if you catch another
  claim like it, fix it rather than working around it.
- Security extraction (`imagescan`): keep the path-traversal/symlink/tar-bomb
  guards; never follow links out of the temp root.
- **binscan sees only what has a symbol to read:** dynamic imports (`.dynsym`
  / needed libraries) are the primary source for ELF/PE/Mach-O; ELF also
  falls back to the full `.symtab` when dynamic imports are empty, so a
  non-stripped statically-linked binary (static OpenSSL/BoringSSL/libsodium,
  a Rust binary on `ring`/`rustls`, a Go binary with crypto compiled in) is
  still caught. A **stripped** static binary has neither `.dynsym` crypto nor
  a `.symtab` and is invisible here; PE/Mach-O have no `.symtab`-style
  fallback at all yet. Don't read a "clear" scan of a statically-linked
  binary as proof of absence. Say so if it comes up.

## Escalate, tell the user, do not just push through
You (any model) cannot switch models. When a task hits the high-stakes criteria
below, **stop and print this line, then wait** for the user to switch or say go:

> `MODEL CHECK: recommend the strongest available model - <one-line reason>.
> Switch now, or proceed on the current one?`

Escalate when the task involves:
- A real architectural fork with expensive rollback (new persistence layer, new
  cross-cutting abstraction, changing the asset/graph model).
- Untangling a conflict or anything **irreversible/outward-facing** (history
  rewrite, force-push, deleting work you didn't create, making the repo public).
- Subtle correctness reasoning where a missed case ships a wrong answer
  (risk-classification edge cases, dedup/graph identity, security guards).
- A multi-step debugging session where the root cause isn't obvious.

Routine increments are fine on a cheaper model: a new connector following the
established pattern, PE/Mach-O-style symmetric extensions, tests, docs, CLI
wiring, dependency bumps. The Plan-Mode-then-approve loop already puts a human
gate in front of the risky decisions, which keeps quality high on any model.

## Memory
Session learnings live in `~/.claude/projects/-Users-factory-Development-Qryx/memory/`
(see `MEMORY.md`). Check it for prior lessons before repeating a class of mistake.
