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
