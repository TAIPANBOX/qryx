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
