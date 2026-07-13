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
