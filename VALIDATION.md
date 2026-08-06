# Live infrastructure validation

Qryx was run against real Linux binaries, a real container image, and a real live TLS endpoint on
disposable Hetzner infrastructure before any public launch - the first time its ELF and TLS detectors
had ever faced anything beyond curated fixtures.

## Robustness against real-world artifacts

- **No crash across 25,586 real Linux ELF files** (stripped, static, PIE, and truncated binaries all
  included) scanned from a live filesystem.
- Container scanning (`docker save` output) and live-TLS version/cipher detection both held up against
  real images and a real endpoint.
- A later run scanned **4 targets at once**: `openssl` and `ssh` binaries, a full `/usr/bin` directory
  (149 findings across 20 unique assets, 4 quantum-vulnerable + 3 weak), and a **live TLS handshake
  against `api.anthropic.com:443`**, correctly flagged ECDSA-256 as quantum-vulnerable.

## Real bugs live testing found (and fixed)

Both invisible on the fixture suite - only real-world binaries surfaced them. Both fixed and merged
before the runs above were taken as final.

1. **ELF detector blind to modern OpenSSL** (`internal/binscan/elf.go`) - the symbol detector only knew
   the legacy flat OpenSSL API, not the OpenSSL 3.x `EVP_*` surface (nor AES, nor libgcrypt), so
   scanning `/usr/bin/openssl` itself came back near-empty. Fixed - `EVP_*` (OpenSSL 3.x) detection now
   confirmed live against the real `openssl` binary in every subsequent run.
2. **Expired-cert lost in a dedup collision** (`internal/graph/graph.go`) - a certificate that was both
   expired *and* quantum-vulnerable collapsed to one graph node keyed on Type/Algorithm/KeySize, silently
   dropping the expired finding from compliance reports (a CI expired-cert gate would have missed it).
   Fixed by adding a risk-class dimension to the asset key.

## What this proves

- The ELF, container, and TLS detectors are robust against real-world input variety, not just the
  fixture corpus.
- Both real-world-only bugs found here are fixed and re-confirmed holding across every subsequent run.
- Post-quantum risk classification (NCSC 2035 timeline) works against a real production TLS endpoint,
  not just a lab certificate.

## Method

Disposable Hetzner VPS boxes (deleted after each run) with real system binaries and container images;
code delivered as a `git archive` tarball (no secrets, no `.git`, no token); the tool bound to
`127.0.0.1` where it ran any local service. Nothing from these runs was ever exposed publicly, and no
infrastructure or secret from the campaign persists today.

## Bugs a read-only audit found (2026-08-05)

Three of them, all the same disease and none of them visible from the output: qryx could not tell
"found nothing" from "could not look", and reported the clean result either way. None was found by a
live run, because every one of them makes a run look successful.

1. **Both drift gates failed open on a missing baseline** (`cmd/qryx/main.go`) - a baseline that could
   not be loaded produced an empty delta, so `--fail-on-new` iterated nothing and passed, and
   `--policy --policy-new-only` evaluated an empty set of new assets, found zero violations and exited
   0. A typo in a CI path, a cache miss or a first run on a new branch turned a blocking gate into a
   green build. Fixed: a missing baseline is an error naming the path whenever a gate reads the
   comparison, with `--allow-missing-baseline` as the explicit opt-in for the genuine first run.
   *(@measured: `qryx scan --baseline <absent> --fail-on-new high <tree>` exits 1 and names the path;
   the same command with `--allow-missing-baseline` exits 0; `--baseline` alone still exits 0,
   2026-08-05)*
2. **Every read and parse failure in the scan path was silent** (`internal/scan/walker.go`,
   `detectors/goast.go`, `detectors/certfile.go`) - unreadable directory entries, failed `Info()`
   calls, files over the 4 MiB read cap, failed reads and files no detector could parse each returned
   with no counter, and `FilesWalked` only counted files that survived all of them. A tree qryx never
   opened reported exactly like a tree with no cryptography in it. Fixed: the three counts are carried
   on `scan.Result` and printed on stderr next to the test-code exclusion line.
   *(@measured: a tree with one unreadable file, one over the cap and one that does not parse reports
   `3 file(s) were not examined: 1 unreadable, 1 over the 4194304-byte size cap, 1 unparsable`, while
   a fully readable tree prints nothing, 2026-08-05)*
3. **`qryx image` reported zero findings for any realistic container image** (`internal/imagescan/
   image.go`) - each outer tar entry was buffered whole and capped at 32 MiB before being sniffed as a
   layer, so a larger layer was truncated, `tar.Next` returned `io.ErrUnexpectedEOF`, and `Scan`
   swallowed the error to one stderr line. The operator saw "No cryptographic assets detected" and
   exit 0. Every Debian- and Ubuntu-based image has layers past that cap. The two existing tests built
   a few-hundred-byte layer in memory, so nothing covered it. Fixed: layers stream through the tar
   reader instead of being buffered, and an image that cannot be extracted is a fatal error naming it.
   *(@measured: a synthetic 40 MiB layer containing one `hashlib.md5()` call scanned as
   "0 findings, exit 0" on `main` at 567c2ce and reports the MD5 finding after the fix; an image with
   a layer cut mid-file exits 1 instead of 0, 2026-08-05)*

## A bug the fixture output was already showing (2026-08-06)

One defect, and unlike the three above it was never invisible: it had been printing an empty
parenthesis into the migration plan of the repository's own sample fixture, in the output every
`--format migration` run produces. Nobody read it.

4. **Terraform-declared assets scored `low` agility, and their source was dropped from the effort
   note** (`internal/agility/agility.go`) - the `sourceAgility` map had no row for `terraform`, and
   `dominantAgility` appended a source name to its result only inside the branch that recognised the
   source, so a single missing row cost two answers. Every key declared in HCL fell through to the
   "unknown source -> assume hardest" fallback and was reported as `low`, "code change + redeploy",
   though a `aws_kms_key` or `azurerm_key_vault_key` in HCL is migrated by editing a key-spec argument
   and running `apply` - `medium` in that file's own vocabulary. The same physical key read back
   through the AWS, GCP or Azure connector scored `high`, so one key's stated difficulty depended on
   which connector happened to see it. Three other sources were missing the same way (`rust`,
   `aiusage`, `agentstack`). Fixed: the four rows added, an unrecognised source is now named in the
   effort note and counts as `low` whatever it sits beside, and the parenthetical is omitted rather
   than printed empty when there is no source to name.
   *(@measured: `qryx scan --format migration testdata/sample` on `main` at 515864e prints
   `"agility": "low"` and `"effort": "code change + redeploy (); 1 occurrence(s)"` for all three
   `main.tf` entries (lines 3, 8 and 16); after the fix the same three read `"agility": "medium"` and
   `"effort": "config/dependency change (terraform); 1 occurrence(s)"`. `summary.toMigrate` stays 6
   and `summary.quickWins` stays 0, a quick win requiring `high` agility. 2026-08-06)*

   The gap that let it ship is that `sourceAgility` is a second copy, kept by hand, of a list that
   lives in the detectors and connectors, and nothing compared them. It is compared now, by
   `internal/agility/sources_test.go`: one test walks `detectors.Default()` and requires a row per
   detector, the other parses the tree for every `Source: "..."` literal inside a `model.Finding`
   composite literal and requires a row per connector. Both fail red on 515864e.
## The migration plan called an unknown a pass (2026-08-06)

The same disease as the three above, one report further on, found by asking where else it had
survived. `agility.target()` returned no migration target for an AES asset whose key size the scan
never read, and an empty target does not mean "unknown" to anything downstream: it means "this asset
already meets the bar", which is why `Assess` returns `ok=false` beside it and why the plan then
leaves the asset out entirely. The guard was `a.KeySize > 0 && a.KeySize < 256`, which reads as
deliberate rather than accidental, so the first question was not how to fix it but whether the
migration plan is the right place to raise an unknown at all.

It is. Eight of the twelve places that build an AES asset leave the size at zero, so the skipped
population is the common shape rather than an edge case: Azure Key Vault `oct` and `oct-HSM` keys,
where the length genuinely is not derivable from public metadata and where both 128 and 192 are
accepted; the same key in Terraform; a `crypto/aes` import; the `AES_` and `EVP_aes_` symbol rules in
binscan; and three identifier patterns in the rust and cryptocall detectors. Two of those match text
naming the size on the very line they matched (`Aes128Gcm`,
`createCipheriv('aes-128-cbc', ...)`) and still do not read it, because the patterns anchor on the
cipher name, so an asset the plan skipped can be a literal AES-128 sitting under a line that says
128.

Nothing here invents a "not assessed" status the migration plan does not have, and that was the
alternative worth rejecting out loud. AES carries no risk class, so the entry sorts below every asset
that has one, the dashboard's top-N priority list cannot be displaced by it, and what the reader gets
is one line saying "go and read this key's length, and here is where you are going if it turns out to
be short". The rationale had to move with it: a single flat string, "AES below 256 bits is below the
CNSA 2.0 minimum", was returned for every AES asset regardless of size, so listing an unread key
without touching that would have stated the shortfall as fact over a length nobody had read, which is
the same defect pointed the other way, in the sentence an operator actually acts on.

**Numbers this moves.** `testdata/aes-unknown-size` goes from `"toMigrate": 0` and a null plan to two
entries, both targeting AES-256-GCM, both carrying the locations to check. This repository's own tree
stays at 3 and `testdata/sample` at 6, since neither contains AES, so nothing previously published
about those two moves. The NCSC verdicts do not move anywhere, on any target: `planStep` is consulted
only for quantum-vulnerable assets, and AES is not one.

This is the plan half only. On this branch `--format cnsa` still grades that same fixture 100%
compliant and still prints "AES-256 is the CNSA 2.0 approved symmetric cipher" over both 128-bit
lines; that half is fixed independently on `fix/aes-unknown-size-is-not-aes-256`, which is where the
fixture comes from (identical bytes, so the two branches can land in either order).

*(@measured: the real binary built from this branch and from `main` at 515864e, run over
`testdata/aes-unknown-size`, this repository's tree and `testdata/sample` for `--format migration`
and `--format ncsc`; plus `go test -race ./...` (200 test functions), `gofmt -l`, `go vet`,
`go build`, `scripts/declared-deps.sh`, `scripts/readme-numbers.sh` and
`scripts/reproducible-build.sh`, 2026-08-06)*
## Numbers this tool published, and signs, that were wrong in its own favour (2026-08-05 audit)

Five more from the same read-only audit, fixed on 2026-08-06 on branch
`fix/numbers-that-flatter-the-scan`, and a sixth (item 6) found afterwards by asking where else
defect 1's shape had survived, fixed on `fix/aes-unknown-size-is-not-aes-256`. Where the first three
were the tool not knowing what it had failed to look at, these are the tool grading what it did look
at, generously, and in every case the error ran the same way: toward a better score, a cleaner
inventory, a bigger finding. A scanner that errs in its own favour is the one thing a security team
will not forgive, because they have no way to audit it except by rebuilding the report by hand.

Item 6 is the follow-through on item 1, on branch `fix/evidence-record-not-assessed`, and it is here
rather than in its own section because it is the same defect: a fix that changed how the score is
computed but stopped short of the record that gets persisted and signed.

**Two of these move numbers that were already published.** The CNSA 2.0 compliance percentage drops
wherever a scan contains cryptography qryx has no rule for, and the evidence digest changes with the
document, so a re-run will not reproduce the digest of an evidence file signed before this branch.
Measured on real targets: this repository's own tree **16% -> 0%**, `testdata/sample` **12% -> 0%**,
the `qryx agents` fixtures **50% -> 0%**. Nothing about the cryptography being scanned changed. What
changed is that SHA-256, X509 and the enclave-key attestation pseudo-assets stopped counting as CNSA
2.0 compliant, which they never were. Item 6 moves the same percentage again, on any scan holding an
AES key whose size was never read; it does not move the three targets above, none of which contains
AES, so the figures in this paragraph still stand.

1. **The compliance score counted anything it did not recognise as compliant** (`internal/report/
   cnsa.go`) - `cnsaStatus`'s final branch returned `compliant` with "No CNSA 2.0 restriction
   identified" for every no-risk asset whose algorithm was not ML-KEM/ML-DSA/SLH-DSA/AES/SHA-384/512.
   That is SHA-256 (not on the CNSA 2.0 list), bcrypt, HMAC, ChaCha20, and X509/OIDC/enclave-key, the
   attestation pseudo-assets `qryx agents` emits, and every algorithm `risk.Classify` has never seen.
   `ScorePct = compliant*100/total`, so a scan of entirely unrecognised cryptography scored 100%, and
   that number is what `--format evidence` signs, what the dashboard prints and what `qryx trend
   --fail-on-regression` gates on. Fixed with a fourth status, `not-assessed`, kept out of the
   compliant count and **in the denominator**: excluding it would flatter exactly the scan that
   deserves it least. All four counts appear in the cnsa JSON, the evidence document, the CNSA HTML
   report and the dashboard, since a reader who cannot see how much was never graded cannot judge the
   percentage.
   *(@measured: `qryx agents --format cnsa internal/agentstack/testdata` reports
   `compliant 2 / notAssessed 0` before and `compliant 0 / notAssessed 2` after, and its evidence
   score moves 50 -> 0; `go test -race ./internal/report/`, 2026-08-06)*
2. **Every misconfiguration was told to enforce TLS 1.3** (`internal/report/cnsa.go`) - `cnsaStatus`
   branched on `Risk.Class` alone, and three unrelated findings share the class `misconfig`: a server
   offering TLS 1.0, an Agent Passport with no attestation method, and an agent-event stream with no
   `prev_hash` chain. The last two are what `qryx agents` exists to produce, so the compliance pack
   the README sells to GRC teams printed TLS advice for the connector the README highlights as the
   stack integration. Remediation now follows the asset's algorithm, which is the field each
   connector already sets to say what it found, and an unrecognised misconfiguration gets the
   detector's own reason plus an admission that qryx has no CNSA 2.0 remediation for it, rather than
   inheriting the TLS line.
   *(@measured: the two `qryx agents` fixture findings print attestation and prev_hash guidance;
   `TestCnsaRemediationForRealAgentstackFindings` runs the real connector over the real fixtures, so
   a rename on either side of the contract fails, 2026-08-06)*
3. **A dependency manifest naming a crypto library became a quantum-vulnerable RSA asset**
   (`internal/scan/detectors/deps.go`) - `cryptography`, `pyopenssl`, `node-forge`, `bouncycastle`
   and `openssl` all mapped to algorithm "RSA", and `risk.Classify` keys purely on the algorithm name
   with no regard for asset type, so a plain `cryptography>=42` line was graded RSA quantum-vulnerable
   HIGH: counted non-compliant, listed in the NCSC 2035 migration set, given a plan entry telling the
   operator to move a manifest line to ML-KEM, and able to trip `--fail-on high`. A library that
   *might* use RSA is not an RSA asset. Each library is now inventoried under its own name with an
   explicit informational risk, the shape `aiusage.go` already used. `strings.Index` also meant only
   the first mention per library per file was reported, and the `openssl` needle matched inside
   `pyopenssl`, inventing a dependency that was not there; detection is per line now, most specific
   name wins.
   *(@measured: a three-line requirements.txt scans as 3 findings collapsing to 1 quantum-vulnerable
   RSA asset before, and 2 informational library assets at their own line numbers after;
   `TestDependencyManifestStaysOutOfTheScoreAndTheMigrationSet` runs the real detector and asserts the
   CNSA, NCSC and migration outputs, 2026-08-06)*
4. **A comment about RSA was counted as a use of RSA** (`internal/scan/detectors/cryptocall.go`) -
   the Python and JS patterns ran against raw file content, so `# TODO: migrate off RSA` produced an
   RSA quantum-vulnerable finding at that line and a docstring naming DES produced a weak one. The
   rust detector has stripped comments and string literals since it was written, and the README says
   so for that row, which made the omission read as a decision rather than a gap. Comments are now
   blanked in both languages and string literals too for the Python identifier patterns; the JS
   patterns keep literals, because node names its algorithm inside one (`createHash('md5')`). An
   unterminated quote gives its bytes back at the newline instead of blanking to end of file, since
   the failure mode of the other choice is a scan that reports clean by not looking.
   *(@measured: a six-line Python file reports RSA-high, DES-high and SHA-256 before, and only the
   real SHA-256 call after; `TestCryptoCallUnterminatedQuoteDoesNotHideTheFile` verified to fail with
   the newline recovery removed, 2026-08-06)*
5. **`qryx gcp` inventoried one KMS location and called it the project** (`internal/cloud/gcp/
   gcp.go`, `cmd/qryx/main.go`) - the parent was `projects/<p>/locations/<location>` with `--location`
   defaulting to `global`, and Cloud KMS key rings are overwhelmingly regional, so a plain
   `qryx gcp --project X` returned near-empty for most real projects and reported it as a clean
   inventory. The API takes `locations/-` as a wildcard, so the scope was a choice. Same family, and
   made more likely by that change: all three cloud connectors ended the whole inventory on the first
   per-resource API error, and a Key Vault policy granting keys/list but not keys/get is an ordinary
   configuration that killed the scan on key one. They skip the resource now, and every skipped
   resource is counted and named on stderr, because nine keys out of ten reported as though they were
   ten is the worse failure. A listing call that fails is still fatal.
   *(@measured: `scanWith` asks its lister for `locations/-` when no location is given and for the
   named one when there is; the AWS, Azure and GCP skip paths are table-tested through the existing
   fakes; the CLI usage line is asserted to carry the new default. No cloud account was used, and the
   real-SDK wiring in `gcpLister.list` stays unverified by design, per CLAUDE.md invariant 4,
   2026-08-06)*
6. **AES whose size was never read was graded as though it were AES-256** (`internal/report/
   cnsa.go`) - the AES branch treated `KeySize == 0 || KeySize >= 256` as compliant, so an asset
   whose key length the scan never established was counted a pass and told the reader "AES-256 is
   the CNSA 2.0 approved symmetric cipher". Size 0 means no size was read, not that it is 256, and
   CNSA 2.0 approves AES at 256 and nothing below: AES-128 and AES-192 are not compliant. This is
   defect 1's disease surviving one branch above it, in a named algorithm, and it is the common
   case rather than an edge one. Eight of the twelve places that build an AES asset leave the size
   at zero: Azure Key Vault `oct` and `oct-HSM` keys, where `keyTypeToAsset`'s own comment says the
   length is not derivable from public metadata while Key Vault and Managed HSM both accept 128 and
   192-bit keys; the same key declared in Terraform; a `crypto/aes` import; the `AES_` and
   `EVP_aes_` symbol rules in binscan; and the three identifier patterns in the rust and cryptocall
   detectors. The four that do supply 256 all read a provider's symmetric default: AWS KMS, GCP KMS,
   and Terraform's aws and google equivalents. Two of the eight match text that names the size on the
   line they matched, `Aes128Gcm` and `createCipheriv('aes-128-cbc', ...)`, and still do not read
   it, because the patterns anchor on the cipher name: so the report was not only passing an
   unknown, it printed a specific wrong number over a source line that said 128. Fixed by splitting
   the branch three ways, 0 to `not-assessed`, `>= 256` compliant, everything between still
   non-compliant, with an action that says the size could not be determined and where to check it.
   Teaching those detectors to extract a size would shrink the not-assessed population but cannot
   empty it, because the Key Vault case has no size to read.
   *(@measured: `qryx scan --format cnsa testdata/aes-unknown-size`, a fixture holding all three
   shapes, scores **100% -> 0%**, `compliant 2 / notAssessed 0` before and `compliant 0 /
   notAssessed 2` after. A real AES-256, an `aws_kms_key` taking `SYMMETRIC_DEFAULT`, still scores
   100%. This repository's tree and `testdata/sample` do not move, 0% -> 0%, because neither
   contains AES. Regression tests `TestCnsaStatusUnknownSizeAESIsNotAssessed` and
   `TestUnknownSizeAESIsNeverReportedAsAES256`, the second running the real detectors over that
   fixture; both were run against the unfixed code first and fail on it, 2026-08-06)*
6. **The fourth count stopped at the report layer, and the record that outlives the run still split
   three ways** (`internal/store/evidence.go`, `internal/store/postgres.go`, `internal/store/
   schema.sql`, `internal/report/evidence.go`, `internal/report/trend.go`, `cmd/qryx/main.go`) -
   item 1 added `not-assessed` to `cnsaSummary` and `evidenceSummary`, but `report.Attestation` and
   `store.EvidenceRecord` kept their three. The record stayed internally consistent, because `Total`
   already counted the ungraded assets, and that is what made it hard to see: nothing was wrong,
   `compliant + nonCompliant + issues` simply no longer reached `total`, and the reader of a
   `--save-evidence` trail or of `qryx trend` had to subtract to find out how much of the denominator
   was never graded. A compliance record whose parts do not add up to its whole is the kind of
   document somebody reconstructs by hand at exactly the wrong moment. All four counts now travel to
   the trail and back out through `qryx trend`, which prints the per-record count and states the
   latest ungraded share against its total when there is one, and says nothing when everything was
   graded. The Postgres backend gains the column through `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`
   in the ensure-schema bootstrap, because `CREATE TABLE IF NOT EXISTS` does nothing to a table that
   already exists and every insert on an existing deployment would have failed. Records written
   before the field decode as 0, which is what they meant.
   *(@measured: against a local `postgres:16`, `TestPostgresTrailCarriesNotAssessed` and
   `TestPostgresTrailBootstrapAddsNotAssessedColumn` both fail on the unfixed backend
   (`NotAssessed = 0, want 1`) and pass after, with the migration test run against a table genuinely
   created without the column; the real binary's `--save-evidence` record reads
   `"issues":0,"notAssessed":1,"total":4` with `1+2+0+1 = 4`; `qryx trend` over a trail mixing a
   pre-field record with a new one prints both and the ungraded-share line;
   `go test -race ./...` and `go test -tags=integration -race ./internal/store/...`, 2026-08-06.
   Note that `TestPostgresTrail`, which predates this change, passes only against a fresh database;
   verified to fail the same way on a re-used one with these tests removed, so it is not caused by
   them, 2026-08-06)*
