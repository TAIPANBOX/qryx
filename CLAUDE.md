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
   plus the scripts, which CI runs and this step did not name until
   2026-08-09, so "all must pass" was a smaller instruction than CI's:
   ```sh
   ./scripts/declared-deps.sh
   ./scripts/readme-numbers.sh
   ./scripts/features-are-bound.sh   # invariant 15
   ./scripts/reproducible-build.sh   # builds from git archive HEAD: run it after committing
   ./scripts/gates-have-teeth.sh     # invariant 12; needs a clean tree
   ```
4. **Verify end-to-end** when possible: build `/tmp/qryx` and run the real
   command on fixtures or a real target.
5. **Commit** one logical change, Conventional Commits (`feat:`/`fix:`/`test:`/
   `docs:`/`refactor:`/`chore:`), end with the `Co-Authored-By` trailer.
6. **Push the branch** and open a PR with `gh` (GitHub `TAIPANBOX/qryx`).
   `main` is protected and refuses a direct push: `build`, `security` and
   `integration` are required checks, and the rule applies to admins too, so
   there is no account here that can put an unverified commit on `main`.
7. **Check CI**: `gh pr checks <n>`; all three must be green before merging.
   `gh pr merge <n> --squash --auto` queues the merge and GitHub performs it
   when they pass. Fix forward if red, never force-push.

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
   user's agreement, not a commit. The justified set is pgx, the AWS, Google and
   Azure SDKs, `hashicorp/hcl/v2` for correct Terraform parsing with `go-cty`
   arriving with it, and `agent-stack-go` for the shared wire contract. Note that
   this is NOT genaryx's rule, which forbids cloud SDKs outright: reaching a
   provider's KMS is this tool's job.
   *(gate: `scripts/declared-deps.sh`, where every allowed entry carries its
   reason, so adding one means writing a justification rather than appending a
   name)*
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

9. **A released binary can be rebuilt, by somebody who does not trust us, from
   the tag it claims to come from.** This tool asks to be believed about another
   organisation's cryptography, so its own supply chain is the first thing a
   security team will look at, and "the source is open" is not an answer to
   them: it always was. The answer is that they can build it and compare the
   checksum. Three flags hold it, `CGO_ENABLED=0`, `-trimpath` and `-s -w`, and
   they must stay identical in `scripts/reproducible-build.sh` and in
   `.github/workflows/release.yml`. Any one of them going missing breaks the
   property in **silence**: the build still succeeds, the binaries simply stop
   matching, and the only person who ever finds out is the one who tried to
   verify us.
   *(gate: `scripts/reproducible-build.sh`, which builds the same source in two
   directories of deliberately different lengths and refuses if a byte differs;
   verified by deleting `-trimpath`, which fails it. Measured against the real
   published artifact on 2026-08-05: `qryx_v0.3.0_darwin_arm64` from the release
   page and a local build of that tag on a different host OS are both
   `0864315d…3c2b`.)*

10. **The release asset names carry no version, and that is a contract with
    the outside world rather than a style choice.** it-rat.com links straight to
    `releases/latest/download/<name>`, an address that resolves only while the
    name is stable, so putting a version back into `out=` in `release.yml` turns
    every download link on that site into a 404 at the next tag. Nothing in CI
    would say so; the person who finds out is somebody trying to install this.
    The version is not lost, it moves into the binary, where `-X main.version`
    already puts it and where `qryx version` reads it back. That is the harder of
    the two places to fake: anything between us and a reader can rename a file,
    and nothing between us and a reader can restamp the bytes.
    *(gate: `scripts/reproducible-build.sh`, which reads `out=` out of the
    workflow and refuses if it contains VERSION, and refuses just as loudly if it
    finds no asset name at all, because a check that goes green once its subject
    has vanished is worse than no check. Verified by breaking: putting the version
    back fails it in all four repositories that share this shape.)*

11. **Every finding `Source` string has a row in `internal/agility`'s
    `sourceAgility` map.** That map is a second copy, kept by hand, of a list
    that actually lives in the detectors and the connectors, and a missing row
    is not a neutral default: the asset falls through to the "assume hardest"
    fallback, is reported as `low` / "code change + redeploy", and its source
    name never reaches the migration plan's effort note, which then renders an
    empty parenthesis. That is not hypothetical. `terraform` shipped as a
    detector and was never added, so every key declared in HCL was scored as a
    code change while the same physical key read through a cloud connector
    scored `high`, and the difference was visible in the repository's own
    fixture output for as long as it existed. An unrecognised source is still
    assumed hardest **and is still named**, because dropping it from the note
    is how the first half stayed invisible.
    *(test: `TestEveryDefaultDetectorHasAnAgilityLevel` walks
    `detectors.Default()` and requires a row per detector;
    `TestEveryFindingSourceLiteralHasAnAgilityLevel` parses the tree for every
    `Source: "..."` literal inside a `model.Finding` composite literal and
    requires a row per connector, and fails loudly if the walk finds no
    literals at all rather than passing on an empty set. Both go red on
    515864e.)*

12. **A check must be able to tell "did not fail" from "did not run", and every
    gate here has been made to fail on purpose to prove it can.** Two of the
    three gates above already refuse when their subject is absent, and
    invariants 9 and 10 say so. Those sentences were true, were established by
    hand once in the session that wrote the script, and nothing re-ran them.

    A text parser does not break loudly: it stops matching and reports success.
    The mutants that proved these gates lived in commit messages and in the
    `*(gate: ...)*` markers above, which is a record of what was true once.
    *(gate: `scripts/gates-have-teeth.sh`, 14 cases: seven real faults each gate
    must catch, three non-faults they must not, and four subjects taken away
    entirely, where the gate must say it measured nothing rather than report
    OK. Every mutation asserts it applied, because a mutation that changed no
    bytes is indistinguishable from a gate that passed.)*

    **What it does not cover.** It cannot test itself. It proves each gate
    catches the faults named in it, not every fault of that kind. It found no
    hole in any of the four.

13. **A provider id is written once, in the detector's own tables, and every
    consumer joins on it.** The AI inventory has two names for one thing: a
    human label ("Anthropic SDK (python)") and a canonical id (`anthropic`).
    The label is prose and may be reworded; the id is a join key that another
    program in the estate correlates against a Passport's declared provider and
    against an observed egress host. A consumer deriving the id from the label
    would be a second copy of the vocabulary, kept by hand, in a repository
    that cannot see this one, which is invariant 11's failure with a longer
    blast radius: `sourceAgility` at least lives in the same tree.

    Two rows carry no provider and that is the design rather than missing data.
    A `framework` row means the tree reaches a model through an indirection
    whose target is chosen by configuration a text scan cannot read, and a
    `local-runtime` row means nothing leaves the machine. Filling either in
    with a guess would put a provider into an inventory that no evidence
    supports.
    *(test: `TestEveryAIUsageLabelHasACanonicalRow` walks all three tables and
    requires a role on every row, failing loudly on an empty walk rather than
    passing on nothing; `TestAIUsageCarriesACanonicalProvider` and
    `TestAIUsageFrameworkNamesNoProvider` hold the two halves at the detector,
    and `TestAIInventoryCarriesProviderAndRole` holds it at the document)*

14. **A manifest needle matches a whole token, never inside a longer word.**
    Manifests carry prose as well as dependencies, and a bare substring reads
    both. `replicate` matched inside "raft-replicated" in a Cargo.toml
    description, and the row that came out named a provider that code has never
    called. A person reading a table might squint at it; a program joining on
    the id reports AI usage that does not exist, which is the one failure an
    inventory cannot survive. Only letters bound a needle: a hyphen, an
    underscore, a slash, a quote, a digit and a line start all stay legal, since
    that is how real package names are spelled.
    *(test: `TestAIUsageManifestNeedleIsAWholeToken`, verified red against the
    real Cargo.toml line that produced it, and
    `TestAIUsageManifestStillMatchesRealPackageNames` beside it, because the
    obvious over-correction is a recall cut nobody would notice: it pins eight
    dependency lines real ecosystems actually write)*

15. **Every scenario in `features/` names a test that exists, and every
    scenario names one at all.** The feature files are what a reader reads
    instead of a diff, and a scenario with no binding is a paragraph describing
    what somebody wanted. A binding pointing at a renamed test is worse, because
    it reads as held. What this does NOT check is that the test asserts what the
    scenario says: the steps are prose and the binding is a pointer, so a
    scenario can drift from its test and stay green. What it catches is the
    pointer breaking, which is the failure that happens on its own.
    *(gate: `scripts/features-are-bound.sh`, which also refuses a feature file
    with no scenarios and reports that it measured nothing rather than passing
    on an empty set. Four cases in `scripts/gates-have-teeth.sh`: a dangling
    binding, an unbound scenario, a reworded step that must NOT fire, and every
    scenario taken away.)*

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

**Held by this file alone: invariants 2, 4 and 6.** Invariants 7 and 8 are
half held. Invariant 3 is `scripts/declared-deps.sh`, invariant 9 is
`scripts/reproducible-build.sh`, and invariant 15 is
`scripts/features-are-bound.sh`. Invariants 13 and 14 are tests: what a script
could check about them is that a table has a role in every row, which the walk
test already does from inside the package, where it can see the tables rather
than grep for them.

Invariant 3 is now `scripts/declared-deps.sh`. Writing it corrected the
invariant's own prose, which listed "pgx, the cloud SDKs, and hcl/v2" and
omitted `agent-stack-go` and `go-cty`, both of which are direct dependencies and
both of which are justified. A list kept in prose drifts from the manifest
exactly this way.

Each allowed entry carries its reason in the script, so adding one means writing
a justification. It fails in both directions, so a dependency disappearing is
caught too. Invariant 5 could be pinned by a test asserting the prober's TLS config
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

- **A missing toolchain fails every gate at once and does not look like one
  problem.** `go.mod` requires `go 1.27` (for stdlib `crypto/mldsa`, FIPS 204).
  This is now a GA release, so `GOTOOLCHAIN=auto` fetches it on a fresh machine
  and the trap is closed. It was open between 2026-08-06 and 2026-08-20, when
  the pin was `toolchain go1.27rc2`: Go does NOT auto-download a release
  candidate, so every script died with `go1.27rc2: not downloaded` and
  `readme-numbers.sh` correctly reported that it had measured nothing. On
  2026-08-09 that read as five separate gate failures across the teeth harness,
  two of them OVEREAGER on an unmutated tree. It was one environment fact
  wearing five masks. Keep the shape in mind, not the RC: when several
  unrelated gates go red together, suspect the environment before the code.
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
